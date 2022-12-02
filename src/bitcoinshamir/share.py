from .exceptions import ChecksumError, ThresholdError, LanguageError
from .BIP39_List import BIP39_List
from .encode import Encode
from .decode import Decode
from typing import List
from hashlib import sha256

wordlist = BIP39_List()
current_version = 0


class Share:
    """
    Share class for holding a single share of a Shamir (k of n) threshold
    scheme. Each share is a coordinate, with an (x, y) value, where x is an
    integer, greater than 1. The secret key is the y value at x = 0. A checksum
    of the key is the value at x = 1. Share values start at x = 2.

    One share is 37 bytes, represented as 27 words. Each word is 11 bits. The
    297th bit from the last word is truncated. The first 32 bytes encode the
    y value of the share. The next byte is the original seed's checksum. The
    next 2 bytes hold  the version, threshold, and x value of the share. The
    version is 5 bits, starting with a value of 0; the threshold is 4 bits,
    starting at 2; and the x value is 7 bits, starting at 2. The last 2 bytes
    are a checksum of the share. Finally, the share checksum is applied as an
    xor to the prior 2-bytes containing the version, threshold, and x value in
    order to avoid long sequences of zeros.

    296-bit share structure:
    [256: Y value]
    [8: Seed checksum]
    [5: Version xor checksum]
    [4: Threshold xor checksum]
    [7: X value xor checksum]
    [16: Checksum]
    """
    def __init__(
            self, X: int, Y: int, threshold: int, seed_checksum: bytes,
            version: int = current_version) -> None:
        """
        Initializes an instance of the Share class, and assignes values for the
        (x, y) coordinate, as well as the version, threshold, and checksums. The
        threshold must be between [2, 17]. The X value must be between [2, 257].
        """
        if not isinstance(threshold, int):
            raise TypeError("The given threshold argument is not of type int.")

        if threshold < 2 or threshold > 17:
            raise ValueError("The given index argument is out of bounds.")

        if not isinstance(X, int):
            raise TypeError("The given X argument is not of type int.")

        if X < 2 or X > 257:
            raise ValueError("The given X argument is out of bounds.")
        
        if len(seed_checksum) < 1:
            raise ValueError("The given seed_checksum was not at least 1 byte.")

        # Encode the 2-byte sequence containing the version, threshold, and
        # X-value in order to get the share's checksum.
        encoded_version = Encode.share_version(version)
        encoded_threshold = Encode.share_threshold(threshold)
        encoded_x = Encode.share_X(X)
        
        # Get the share checksum, which is the last two bytes of the fully
        # encoded share.
        share_bytes = Encode.share_bytes(
                encoded_x, Y, encoded_threshold, seed_checksum[:1], version
            )

        share_checksum = share_bytes[-2:]

        # Assign instance variables.
        self.seed_checksum = seed_checksum[:1]
        self.X = X
        self.Y = Y
        self.threshold = threshold
        self.version = version
        self.share_checksum = share_checksum
    

    @classmethod
    def from_share_phrase(cls, phrase: List[str], language: str) -> "Share":
        """
        Returns an instance of a Share class according to the given share
        phrase. Raises an error if the language is not in the current language
        list, the mnemonic phrase has invalid words, or has the wrong number of
        words.
        """
        if language not in BIP39_List.LANGUAGE_LIST:
            raise ValueError(f"{language} not in the current language list.")

        if not isinstance(phrase, list):
            raise TypeError("The given phrase was not of the list[str] type.")
        
        if len(phrase) != 27:
            raise ValueError("The given share phrase did not have 27 words.")

        for word in phrase:
            if language not in wordlist.get_language(word):
                raise ValueError(f"\"{word}\" not in {language} word list.")

        indices = [wordlist.get_word_index(word, language) for word in phrase]
        
        # Add words from left to right, shifting the added words to the left by
        # 11 bits each iteration.
        share_int = 0

        for word_index in indices:
            share_int <<= 11
            share_int += word_index
        
        # Remove the last bit because a 27-word phrase has an extra bit that
        # should be ignored.
        share_int >>= 1

        # Truncate the right 40 bits to get the Y-value of the share. The
        # Y-value is the left-most 256 bits, with 40 bits to its right.
        y_int = share_int >> 40

        # The seed checksum value is the 5th byte from the right.
        seed_checksum_int = (share_int & 0xFF_00_00_00_00) >> 32
        seed_checksum_bin = seed_checksum_int.to_bytes(1, "big")

        # The next 2 bytes are version, threshold, and X-value.
        version_threshold_x_val = (share_int & 0xFF_FF_00_00) >> 16

        # The final 2 bytes is the share checksum.
        share_checksum_int = share_int & 0xFF_FF

        # The version, threshold, and X-value are encoded with an xor of the
        # share's checksum to avoid excessive zeros in the share. This xor needs
        # to be removed before decoding each value.
        version_threshold_x_val ^= share_checksum_int

        version_encoded = version_threshold_x_val & 0b11111_0000_0000000
        threshold_encoded = version_threshold_x_val & 0b00000_1111_0000000
        x_val_encoded = version_threshold_x_val & 0b00000_0000_1111111

        version_int = Decode.share_version(version_encoded)
        threshold_int = Decode.share_threshold(threshold_encoded)
        x_int = Decode.share_X(x_val_encoded)

        return cls(seed_checksum_bin, x_int, y_int, threshold_int, version_int)


    def to_bytes(self) -> bytes:
        """
        returns the 37-byte representation of the current Share instance.
        """
        # The version, threshold, and X-value are encoded in the same 2-byte
        # sequence.
        version = Encode.share_version(self.version)
        threshold = Encode.share_threshold(self.threshold)
        x_val = Encode.share_X(self.X)

        share_bytes = Encode.share_bytes(
                x_val, self.Y, threshold, self.seed_checksum, version
            )
        
        return share_bytes

    
    def get_word(self, index: int, language: str) -> str:
        """
        Returns the word at the given zero-based index of this Share class
        instance. Raises error if the index is not between 0 and 26.
        """
        if not isinstance(index, int):
            raise TypeError("The index argument given is not an int.")

        if index < 0 or index > 26:
            raise IndexError("The index argument given is out of bounds.")
            
        if language not in BIP39_List.LANGUAGE_LIST:
            raise ValueError(f"{language} not in the current language list.")

        # The version, threshold, and X-value are encoded in the same 2-byte
        # sequence.
        version_int = Encode.share_version(self.version)
        threshold_int = Encode.share_threshold(self.threshold)
        x_int = Encode.share_X(self.X)

        share_bytes = Encode.share_bytes(
                x_int, self.Y, threshold_int, self.seed_checksum, version_int
            )
        
        # Rehash the share to get the extra bit for the 27th word.
        version_threshold_x_int = version_int + threshold_int + x_int
        version_threshold_x_bin = version_threshold_x_int.to_bytes(2, "big")

        share_bytes_before_checksum = [
            self.Y.to_bytes(32, "big"),
            self.seed_checksum,
            version_threshold_x_bin
        ]

        third_checksum_byte = sha256(b"".join(share_bytes_before_checksum))[2:3]

        # Join the share bytes and remove 7 bits from the third byte of the
        # share checksum.
        share_byte_array = [
            share_bytes,
            third_checksum_byte
        ]

        share_bin = b"".join(share_byte_array)
        share_int = int.from_bytes(share_bin, "big")
        share_int >>= 7

        # Determine number of bits to truncate from the right based the word's
        # position in the phrase.
        max_words = 27
        word_position = index + 1
        remove_word_count = max_words - word_position
        truncated_share_int = share_int >> (remove_word_count * 11)

        # Get word index and return word text.
        word_bitmask = 0b1111_1111_111
        word_index = truncated_share_int & word_bitmask
        word = wordlist.get_word(word_index, language)

        return word


    def is_valid(self) -> bool:
        pass