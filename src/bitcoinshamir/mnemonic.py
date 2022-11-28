from .BIP39_List import BIP39_List
import hashlib
from typing import List

wordlist = BIP39_List()

class Mnemonic:
    """
    Mnemonic class for holding a BIP44 seed phrase. The 24 words represent 264
    bits. The first 256 bits are 24 words from a BIP39 word list. The final 8
    bits represent a checksum, which is the first 8 bits of the sha256 hash of
    the first 260 bits of the mnemonic.
    """
    def __init__(self, language: str) -> None:
        """
        Initializes a new instance of the Mnemonic class, and sets the language
        attribute. Raises a ValueError if the language is not in the current
        list of languages.
        """
        if language in BIP39_List.LANGUAGE_LIST:
            self.language = language
            self.seed = bytes(32)
            self.checksum = bytes(1)
        else:
            raise ValueError(f"{language} not in the current language list.")


    def set_word(self, index: int, word: str) -> None:
        """
        Sets a word in this Mnemonic class instance according to the zero-based
        array and word given. Raises errors if the index is out of range or the
        language is not in the current list of languages.
        """
        if not isinstance(index, int):
            raise TypeError("The index argument given is not an int.")

        if index < 0 or index > 23:
            raise IndexError("The index argument given is out of bounds.")

        if self.language not in wordlist.get_language(word):
            raise ValueError(f"{word} not found in {self.language} list.")

        bin_text = bin(int.from_bytes(self.seed, "big"))[2:]


    def is_valid_phrase(phrase: List[str], language: str) -> bool:
        """
        Returns true if the given mnemonic phrase has words that exist in the
        given language's word list, and the checksum is valid. Raises error if
        the language given is not in the current language list.
        """
        if language not in BIP39_List.LANGUAGE_LIST:
            raise ValueError(f"{language} not in the current language list.")

        is_valid_wordcount = len(phrase) == 24
        has_valid_words = all(
            [language in wordlist.get_language(word) for word in phrase]
            )

        if not is_valid_wordcount or not has_valid_words:
            return False

        word_indices = [wordlist.get_word_index(word) for word in phrase]
        bin_text_chunks = [format(index, "011b") for index in word_indices]
        bin_text = "".join(bin_text_chunks)

        # The seed is the first 256 bits. The checksum is the last 8 bits.
        seed_val = int(bin_text[:256], base=2).to_bytes(32, "big")
        checksum = int(bin_text[256:8], base=2).to_bytes(1, "big")

        # The checksum is the first byte of the sha256 hash of the prior 32
        # bytes.
        recalculated_checksum = hashlib.sha256(seed_val).digest()[:1]
        is_valid_checksum = checksum == recalculated_checksum

        return is_valid_checksum
