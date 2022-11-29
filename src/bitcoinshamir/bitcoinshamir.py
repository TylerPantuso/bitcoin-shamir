import os
import lagrange
from typing import List
from .point import Point
from .polynomial import Polynomial

# The field size is a prime number that should be near the max value of the
# secret key. The BIP39 24-word seed phrase creates the largest seed phrase,
# which is 256 bits, plus an 8-bit checksum.
PRIME_MODULUS = 2 ** 256 - 2 ** 32 - 977


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

    # Create shares based on x = 1, x = 2, ... x = (k - 1)
    shares = []

    for i in range(sharecount):
        point = Point()
        point.X = i + 1
        point.Y = polynomial.solve(point.X, PRIME_MODULUS)
        shares.append(point)

    return shares


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
