from .enums import Checksum, Language

class ChecksumError(Exception):
    """
    Exception raised when a checksum is invalid.
    """
    def __init__(self, checksum_type: Checksum, first_checksum: bytes,
            second_checksum: bytes, *args: object) -> None:
        super().__init__(*args)
        self.checksum_type = checksum_type
        self.first_checksum = first_checksum
        self.second_checksum = second_checksum


    def __str__(self) -> str:
        message = "The {0} values did not match\n1:\t{1}\n2:\t{2}"

        return message.format(
            self.checksum_type.value, self.first_checksum, self.second_checksum
        )


class ThresholdError(Exception):
    """
    Exception raised when number of shares provided do not meet the threshold.
    """
    def __init__(self, threshold: int, actual: int, *args: object) -> None:
        super().__init__(*args)
        self.threshold = threshold
        self.actual = actual


    def __str__(self) -> str:
        message = "{0} does not meet the minimum threshold of {1}"
        return message.format(self.actual, self.threshold)


class LanguageError(Exception):
    """
    Exception raised when a word or language is not found.
    """
    def __init__(self, language: Language, *args: object) -> None:
        super().__init__(*args)
        self.language = language


    def __str__(self) -> str:
        return f"'{self.language}' not found in the current language list."


class WordlistError(Exception):
    """
    Exception raised when a word is not found in a BIP39 word list.
    """
    def __init__(self, word: str, language: Language, *args: object) -> None:
        super().__init__(*args)
        self.word = word
        self.language = language


    def __str__(self) -> str:
        return f"'{self.word}' not found in {self.language} word list."