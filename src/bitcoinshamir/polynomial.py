class Polynomial:
    """
    Polynomial class for storing coefficients of a polynomial in a finite
    field.
    """
    def __init__(self, x0 = 0) -> None:
        """
        Creates a new Polynomial class, setting the x^0 coefficient to the given
        input. If no input is given, the x^0 coefficient is set to 0.
        """
        self.coefficients = [x0]


    def __repr__(self) -> str:
        """
        Returns a string representation of this Polynomial class instance.
        """
        components = []

        for i, coefficient in reversed(enumerate(self.coefficients)):
            if i > 0:
                components.append(f"{coefficient}x^{i}")
            else:
                components.append(f"{coefficient}")

        expression = " +\n".join(components)

        return f"Polynomial():\n{expression}"


    def solve(self, x: int, modulus: int) -> int:
        """
        Returns the Y value of the current polynomial coefficients based on the
        given X value.
        """
        result = 0

        for i, coefficient in enumerate(self.coefficients):
            result += coefficient * x ** i % modulus
        
        return result % modulus