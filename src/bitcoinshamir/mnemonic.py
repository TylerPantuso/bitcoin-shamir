from .exceptions import LanguageError, WordlistError
from .BIP39_List import BIP39_List
from .encode import Encode
from .decode import Decode
from hashlib import sha256
from typing import List
import os

wordlist = BIP39_List()

class Mnemonic:
    """
    Mnemonic class for holding a 24-word BIP44 seed phrase. The Mnemonic holds
    33 bytes. The first 32 bytes are the seed. The last byte is a checksum.
    """
    def __init__(self, language: str) -> None:
        """
        Initializes a new instance of the Mnemonic class, and sets the language.
        """
        if language in BIP39_List.LANGUAGE_LIST:
            self.language = language
            self.seed = bytes(32)
            self.checksum = bytes(1)
        else:
            raise LanguageError(language)


    @classmethod
    def generate_random(cls, language: str) -> "Mnemonic":
        """
        Generates and returns a random mnemonic phrase using os.urandom(), which
        is suitable for cryptographic use.
        """
        if language in BIP39_List.LANGUAGE_LIST:
            mnemonic = cls(language)
            mnemonic.seed = os.urandom(32)
            mnemonic.checksum = sha256(mnemonic.seed).digest()[:1]
        else:
            raise LanguageError(language)

        return mnemonic


    def set_word(self, phrase_index: int, word: str) -> None:
        """
        Sets a word in this Mnemonic class instance according to the zero-based
        array and word given. Raises errors if the index is out of range or the
        language is not in the current list of languages.
        """
        if not isinstance(phrase_index, int):
            raise TypeError("The index argument given is not an int.")

        if phrase_index < 0 or phrase_index > 23:
            raise IndexError("The index argument given is out of bounds.")

        if self.language not in wordlist.get_language(word):
            raise WordlistError(word, self.language)

        # Create a deleting bitmask based on the word's position in the phrase.
        max_words = 24
        word_position = phrase_index + 1
        word_count_right_side = max_words - word_position

        word_delete_bitmask = 2 ** 264 - 1
        word_delete_bitmask ^= 0b1111_1111_111 << (word_count_right_side * 11)

        # Delete the current bits at the given word index.
        mnemonic_int = Decode.mnemonic_int(self.seed, self.checksum)
        mnemonic_int &= word_delete_bitmask

        # Set the word bits at the given word index.
        word_bits = wordlist.get_word_index(word, self.language)
        mnemonic_int |= word_bits << (word_count_right_side * 11)

        # Recalculate the checksum if the last word, which contains the
        # checksum, is not the word being set.
        if phrase_index != 23:
            # Get the hash of the first 32 bytes.
            seed_int = mnemonic_int >> 8
            seed_bin = seed_int.to_bytes(32, "big")
            checksum_bin = sha256(seed_bin).digest()[:1]
            checksum_int = int.from_bytes(checksum_bin, "big")
            
            # Delete last byte and replace with the checksum.
            mnemonic_int >>= 8
            mnemonic_int <<= 8
            mnemonic_int &= checksum_int
            
        # Update class instance variables
        self.seed = Encode.mnemonic_seed(mnemonic_int)
        self.checksum = Encode.mnemonic_checksum(mnemonic_int)


    def get_word(self, index: int) -> str:
        """
        Returns the word at the given zero-based index of this Mnemonic class
        instance. Raises error if the index is not between 0 and 23.
        """
        if not isinstance(index, int):
            raise TypeError("The index argument given is not an int.")

        if index < 0 or index > 23:
            raise IndexError("The index argument given is out of bounds.")

        # Determine number of bits to truncate from the right based the word's
        # position in the phrase.
        max_words = 24
        word_position = index + 1
        word_count_right_side = max_words - word_position

        mnemonic_int = Decode.mnemonic_int(self.seed, self.checksum)
        truncated_mnemonic_int = mnemonic_int >> (word_count_right_side * 11)

        # Get word index and return word text.
        word_bitmask = 0b1111_1111_111
        word_index = truncated_mnemonic_int & word_bitmask
        word = wordlist.get_word(word_index, self.language)

        return word


    def validate_phrase(phrase: List[str], language: str) -> bool:
        """
        Returns true if the given mnemonic phrase has words that exist in the
        given language's word list, and the checksum is valid. Raises error if
        the language given is not in the current language list.
        """
        if language not in BIP39_List.LANGUAGE_LIST:
            raise LanguageError(language)

        if len(phrase) != 24:
            raise ValueError("Phrase does not have 24 words")

        for word in phrase:
            if language not in wordlist.get_language(word):
                raise WordlistError(word, language)

        # Add words from left to right, shifting the added words to the left by
        # 11 bits each iteration.
        indices = [wordlist.get_word_index(word, language) for word in phrase]
        mnemonic_int = 0

        for word_index in indices:
            mnemonic_int <<= 11
            mnemonic_int += word_index

        # Validate checksum.
        given_phrase_seed = Encode.mnemonic_seed(mnemonic_int)
        given_phrase_checksum = Encode.mnemonic_checksum(mnemonic_int)
        recalculated_checksum = sha256(given_phrase_seed).digest()[:1]
        
        is_valid_checksum = given_phrase_checksum == recalculated_checksum

        return is_valid_checksum
