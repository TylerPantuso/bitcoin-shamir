import os
import lagrange
from typing import List
from .point import Point
from .polynomial import Polynomial

# TODO: Check all places where random keys are generated, and check for 0
# values.

# The field size is a prime number that should be near the max value of the
# secret key. The BIP39 24-word seed phrase creates the largest seed phrase,
# which is 256 bits, plus an 8-bit checksum.
PRIME_MODULUS = 2 ** 256 - 2 ** 32 - 977

# TODO: Have this return a list of Share objects and switch the key with a
# Mnemonic class
def create_shares(threshold: int, sharecount: int, key: bytes) -> List[Point]:
    """
    Splits a secret key into a (k, n) threshold scheme according to the Shamir
    Secret Sharing (SSS) system. The secret key can be recovered with any
    combination of k number of shares, but no information is revealed about the
    secret key, even with k - 1 shares.
    """
    # Create a polynomial of k - 1 degrees and set the x^0 coefficient to the
    # secret key.
    key_num = int.from_bytes(key, "big")
    polynomial = Polynomial(key_num)

    # Add random 240-bit coefficients.
    for i in range(threshold - 1):
        random_coefficient = int.from_bytes(os.urandom(32), "big")
        polynomial.coefficients.append(random_coefficient)

    # Create shares based on x = 1, x = 2, ..., x = (k - 1)
    shares = []

    for i in range(sharecount):
        point = Point()
        point.X = i + 1
        point.Y = polynomial.solve(point.X, PRIME_MODULUS)
        shares.append(point)

    return shares

# TODO: Make a recover_mnemonic function.
def recover_key(shares: List[Point]) -> bytes:
    """
    Takes a list of Point objects, and uses Lagrange interpolation to find the
    Y-intercept, which is the secret key. If incorrect or too few Point objects
    are provided, an incorrect result will be returned. There is no error
    checking.
    """
    point_list = [(share.X, share.Y) for share in shares]
    key_int = lagrange.interpolate(point_list, PRIME_MODULUS)
    key_bin = key_int.to_bytes(32, "big")

    return key_bin


def interpolate(points: List[Point], modulus: int, X: int) -> int:
    """
    Gets the X-value using Lagrange interpolation according to the given list of
    points, over the finite field of the given modulus. Raises an error if the
    modulus is less than 3 or if the given Point objects do not have int values.
    """
    # Validate the given arguments.
    if not isinstance(modulus, int):
        raise TypeError("The given modulus was not of the int type.")

    if modulus < 3:
        raise ValueError("The given modulus was not a positive prime number.")

    if not isinstance(points, list):
        raise TypeError("The given points argument was not of type list.")

    if len(points) < 2:
        raise ValueError(f"Only {len(points)} given. At least two required.")
    else:
        for point in points:
            if not isinstance(point.X, int) or not isinstance(point.Y, int):
                raise TypeError("The given point values are not of type int.")
            elif point.X < 0 or point.Y < 0:
                raise ValueError(f"({point.X}, {point.Y}) has negative value.")

    # This will be the return value.
    cumulative_sum = 0

    # Sum loop.
    for point_a in points:
        cumulative_product = point_a.Y

        # Product loop.
        for point_b in [p for p in points if p is not point_a]:
            numerator = (X - point_b.X) % modulus
            denominator = (point_a.X - point_b.X) % modulus

            # Multiplicitive inverse using Fermat's little theorem.
            mul_inv = pow(denominator, modulus - 2, modulus)
            product = numerator * mul_inv % modulus
            cumulative_product = cumulative_product * product % modulus

        cumulative_sum = (cumulative_sum + cumulative_product) % modulus

    return cumulative_sum
