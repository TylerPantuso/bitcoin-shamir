class Decode:
    @staticmethod
    def share_X(encoded_X: int) -> int:
        """
        Returns the actual X-value of a Share object based on the given
        encoded X-value.
        """
        # The decoded X-value starts at 2.
        return encoded_X + 2


    @staticmethod
    def share_threshold(encoded_threshold: int) -> int:
        """
        Returns the actual threshold of a Share object based on the given
        encoded threshold value.
        """
        # Get the encoded threshold value by truncating the last 7 bits. The
        # threshold is the second item encoded in a 2-byte sequence, followed by
        # the X-value.
        decoded_threshold = encoded_threshold >> 7

        # The decoded threshold starts at 2.
        return decoded_threshold + 2


    @staticmethod
    def share_version(encoded_version: int) -> int:
        """
        Returns the given version number as the encoded value in a Share
        object.
        """
        # Get the version number by truncating the last 11 bits. The version
        # number is the first item encoded in a 2-byte sequence, followed by the
        # threshold and the X-value.
        return encoded_version >> 11


    @staticmethod
    def mnemonic_int(seed: bytes, checksum: bytes) -> int:
        """
        Returns the integer representation of a Mnemonic class instance.
        """
        return int.from_bytes(seed + checksum, "big")


    @staticmethod
    def mnemonic_key(seed_or_full_mnemonic: bytes) -> int:
        """
        Returns the integer key of a Mnemonic class instance.
        """
        key_bytes = seed_or_full_mnemonic[:32]
        return int.from_bytes(key_bytes, "big")