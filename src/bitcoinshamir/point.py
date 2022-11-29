class Point:
    """
    Point class for storing X, Y coordinates.
    """
    def __init__(self, X: int = 0, Y: int = 0) -> None:
        """
        Creates a new Point class, setting the X & Y values both to 0.
        """
        self.X = X
        self.Y = Y


    def __repr__(self) -> str:
        """
        Returns a string representation of this Point class instance.
        """
        return f"Point({self.X}, {self.Y})"