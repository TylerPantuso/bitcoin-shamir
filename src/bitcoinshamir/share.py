from .BIP39_List import BIP39_List
from typing import List
import hashlib

wordlist = BIP39_List()

class Share:
    """
    Share class for holding a single share of a Shamir (k of n) threshold
    scheme. Each share is a coordinate, with an (x, y) value, where x is an
    integer, greater than 0. The secret key is assumed to be the y value at
    x = 0. One share has 264 bits total, represented as 24 words. Each word is
    11 bits. The first 240 bits encode the Y value of the share. The next 8 bits
    are the original seed's checksum. The next 3 bits are the threshold starting
    at 2, xor the first 3 bits of the share's final checksum. The next 5 bits
    are the X value starting at 1, xor the last 5 bits of the share's final
    checksum. The final 8 bits is the share's checksum of all 256 bits preceding
    it, which is the first 8 bits of the sha256 hash.

    [240: Y value]
    [8: Seed checksum]
    [3: Threshold xor checksum]
    [5: X value xor checksum]
    [8: Checksum]
    """
    def __init__(
            self, seed_checksum: bytes,
            X: int, Y: int, threshold: int) -> None:
        """
        Initializes an instance of the Share class, and assignes values for the
        (x, y) values, as well as the threshold and checksums. The threshold
        should be a value between the inclusive bounds of 2 and 9. The X value
        should be a value between the inclusive bounds of 1 and 32.
        """
        if not isinstance(threshold, int):
            raise TypeError("The given threshold argument is not of type int.")

        if threshold < 2 or threshold > 9:
            raise ValueError("The given index argument is out of bounds.")

        if not isinstance(X, int):
            raise TypeError("The given X argument is not of type int.")

        if X < 1 or X > 32:
            raise ValueError("The given X argument is out of bounds.")
        
        if len(seed_checksum) < 1:
            raise ValueError("The given seed_checksum was not at least 1 byte.")

        self.seed_checksum = seed_checksum[:1]
        self.X = X
        self.Y = Y
        self.threshold = threshold
    

    @classmethod
    def from_mnemonic_phrase(cls, phrase: List[str], language: str) -> "Share":
        """
        Returns an instance of a Share class according to the given mnemonic
        phrase. Raises an error if the language is not in the current language
        list, the mnemonic phrase has invalid words, or has the wrong number of
        words.
        """
        if language not in BIP39_List.LANGUAGE_LIST:
            raise ValueError(f"{language} not in the current language list.")

        if not isinstance(phrase, list):
            raise TypeError("The given phrase was not of the list[str] type.")
        
        if len(phrase) != 24:
            raise ValueError("The given phrase did not have 24 words.")

        for word in phrase:
            if language not in wordlist.get_language(word):
                raise ValueError(f"\"{word}\" not in {language} word list.")

        indices = [wordlist.get_word_index(word, language) for word in phrase]
        bin_text_chunks = [format(index, "011b") for index in indices]
        bin_text = "".join(bin_text_chunks)

        # The Y value is the first 240 bits.
        y_val = int(bin_text[:240], base=2)

        # The original seedphrase checksum is the next 8 bits.
        seed_checksum = int(bin_text[240:8], base=2).to_bytes(1, "big")

        # The threshold and X value are the next 8 bits. These values still have
        # an xor of the final checksum applied, which will need to be removed.
        threshold_x_xor = int(bin_text[248:8]).to_bytes(1, "big")

        # The final checksum is the last 8 bits.
        hash_byte = int(bin_text[256:8], base=2).to_bytes(1, "big")

        # Remove xor from threshold and X value
        threshold_x = threshold_x_xor ^ hash_byte
        threshold_x_bin_text = format(int.from_bytes(threshold_x, "big"), "08b")

        # The first 3 bits are the threshold. The threshold starts with a value
        # of 2, encoded as 0, so the threshold is 2 plus the encoded value.
        threshold = int(threshold_x_bin_text[:3], base=2) + 2
        
        # The last 5 bits are the X value. The X value starts with a value of 1,
        # encoded as 0, so the X value is 1 plus the encoded value.
        x_val = int(threshold_x_bin_text[3:5], base=2) + 1

        return cls(seed_checksum, x_val, y_val, threshold)


    def to_bytes(self) -> bytes:
        """
        returns the 33-byte representation of the current Share instance.
        """
        y_bin = self.Y.to_bytes(30, "big")

        # The X value starts at 1, which is encoded as 0.
        x_bin = (self.X - 1).to_bytes(1, "big")

        # The threshold starts at 2, which is encoded as 0.
        threshold_bin = (self.threshold - 2).to_bytes(1, "big")

        threshold_x_string = format(threshold_bin, "03b") + format(x_bin, "05b")
        threshold_x_bin = int(threshold_x_string, base=2).to_bytes(1, "big")

        initial_bin = y_bin + self.seed_checksum + threshold_x_bin
        hash_byte = hashlib.sha256(initial_bin).digest()[:1]

        threshold_x_xor = threshold_x_bin ^ hash_byte

        return y_bin + self.seed_checksum + threshold_x_xor + hash_byte


    def is_valid(self) -> bool:
        pass