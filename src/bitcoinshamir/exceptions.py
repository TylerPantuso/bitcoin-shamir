class ChecksumError(Exception):
    """
    Exception raised when a checksum is invalid.
    """
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


    def __str__(self) -> str:
        return super().__str__()

class ThresholdError(Exception):
    """
    Exception raised when number of shares provided do not meet the threshold.
    """
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


    def __str__(self) -> str:
        return super().__str__()

class LanguageError(Exception):
    """
    Exception raised when a word or language is not found.
    """
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


    def __str__(self) -> str:
        return super().__str__()

