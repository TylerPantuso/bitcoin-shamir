from hashlib import sha256

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


    @staticmethod
    def share_bytes(
            encoded_X: int, encoded_Y: int, encoded_threshold: int,
            seed_checksum: bytes, encoded_version: int) -> bytes:
        """
        Returns the bytes of a share based on the given values of a share.
        """
        # Combine the version, threshold, and X-value into the same 2-byte
        # sequence.
        version_threshold_x = encoded_version + encoded_threshold + encoded_X
        version_threshold_x_bin = version_threshold_x.to_bytes(2, "big")

        # The share checksum is the first two bytes of the sha256 hash of all
        # previous bytes.
        share_bytes_before_checksum = [
            encoded_Y.to_bytes(32, "big"),
            seed_checksum,
            version_threshold_x_bin
        ]

        share_checksum = sha256(b"".join(share_bytes_before_checksum))[:2]
        share_checksum_int = int.from_bytes(share_checksum, "big")

        # Xor the share cheksum to the version, threshold, and X-value.
        version_threshold_x_xor = version_threshold_x ^ share_checksum_int

        # Join and return the share bytes.
        share_bytes = [
            encoded_Y.to_bytes(32, "big"),
            seed_checksum,
            version_threshold_x_xor.to_bytes(2, "big"),
            share_checksum
        ]

        return b"".join(share_bytes)