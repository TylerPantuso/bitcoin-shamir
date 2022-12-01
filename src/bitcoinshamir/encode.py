class Encode:
    @staticmethod
    def share_X(unencoded_X: int) -> int:
        """
        Returns the given X-value as the encoded value in a Share object.
        """
        # The actual X-value starts at 2, so the encoded version is 2 less than
        # the given value.
        return unencoded_X - 2

    @staticmethod
    def share_threshold(unencoded_threshold: int) -> int:
        """
        Returns the given threshold value as the encoded value in a Share
        object.
        """
        # The actual threshold starts at 2, so the encoded version is 2 less
        # than the given value.
        encoded_threshold = unencoded_threshold - 2

        # The threshold is the second item encoded in a 2-byte sequence. The
        # X-value to its right takes 7 bits, so the threshold needs to be
        # shifted to the left by 7 bits.
        encoded_threshold <<= 7

        return encoded_threshold

    @staticmethod
    def share_version(unencoded_version: int) -> int:
        """
        Returns the given version number as the encoded value in a Share
        object.
        """
        # The version is the first item encoded in a 2-byte sequence. The
        # version and X-value to its right take 11 bits, so the version needs
        # to be shifted to the left by 11 bits.
        return unencoded_version << 11
