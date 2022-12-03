from .point import Point
from typing import List

class Lagrange:
    """
    Class containing static methods for caluclating lagrange interpolation.
    """
    @staticmethod
    def interpolate(points: List[Point], modulus: int, X: int) -> int:
        """
        Gets the Y-value using Lagrange interpolation according to the given
        list of points, over the finite field of the given modulus.
        """
        if not isinstance(modulus, int):
            raise TypeError("The given modulus was not of the int type.")

        if modulus < 3:
            raise ValueError("The given modulus was out of bounds.")

        if not isinstance(points, list):
            raise TypeError("The given points argument was not of type list.")

        if len(points) < 2:
            message = f"At least 2 points required. Only {len(points)} given."
            raise ValueError(message)

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