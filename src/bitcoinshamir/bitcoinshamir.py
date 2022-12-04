import os
import lagrange
from typing import List
from .exceptions import ChecksumError, ThresholdError
from .enums import Checksum, Language
from .point import Point
from .share import Share
from .encode import Encode
from .decode import Decode
from .lagrange import Lagrange
from .mnemonic import Mnemonic
from .polynomial import Polynomial


# The field size should be a prime number that is larger than the max value of
# the secret key (256 bits).
PRIME_MODULUS = 2 ** 256 - 2 ** 32 - 977


def create_shares(
        threshold: int, sharecount: int, mnemonic: Mnemonic
        ) -> List[Share]:
    """
    Splits a 24-word BIP39 mnemonic into a (k, n) threshold scheme, based on the
    Shamir Secret Sharing (SSS) system. The secret key can be recovered with any
    combination of k number of shares, but no information is revealed about the
    secret key, even with k - 1 shares.
    """
    if not isinstance(threshold, int):
        raise TypeError("The threshold argument was not of the int type.")

    if threshold < 2 or threshold > 17:
        raise ValueError("The given index argument is out of bounds.")

    if not isinstance(sharecount, int):
        raise TypeError("The sharecount argument was not of the int type.")

    if sharecount < threshold or sharecount > 256:
        raise ValueError("The given sharecount argument is out of bounds.")

    # f(x=0) is the key value.
    key_num = Decode.mnemonic_key(mnemonic.seed)
    key_point = Point(0, key_num)
    
    # f(x=1) is the key hash.
    key_hash = Encode.mnemonic_hash(key_num)
    hash_num = int.from_bytes(key_hash, "big")
    hash_point = Point(1, hash_num)

    # All f(x>1) are the share values.
    shares = []

    # Generate 2 fewer shares with random X-values than the threshold, because
    # the key value at x=0 and the hash at x=1 are already determined.
    random_share_count = threshold - 2

    for i in range(random_share_count):
        # The X-value for random shares start at x=2.
        x_val = i + 2
        random_val = int.from_bytes(os.urandom(32), "big")

        point = Point(x_val, random_val)
        share = Share(point, threshold, mnemonic.checksum)
        shares.append(share)

    # Calculate the remaining shares using Lagrange interpolation.
    base_points = []
    base_points.append(key_point)
    base_points.append(hash_point)
    base_points.extend([share.point for share in shares])
    
    calculated_share_count = sharecount - random_share_count

    for i in range(calculated_share_count):
        x_val = i + random_share_count + 2
        y_val = Lagrange.interpolate(base_points, PRIME_MODULUS, x_val)
        
        point = Point(x_val, y_val)
        share = Share(point, threshold, mnemonic.checksum)
        shares.append(share)

    return shares


def recover_mnemonic(shares: List[Share]) -> Mnemonic:
    """
    Calculates and returns a Mnemonic object based on the given Share objects.
    Raises an error if the shares are not valid.
    """
    if not isinstance(shares, list):
        raise TypeError("The given shares argument was not a list object.")

    first_seed_checksum = shares[0].seed_checksum

    for share in shares:
        if not isinstance(share, Share):
            message = "The shares argument was not of the type List[Share]."
            raise TypeError(message)
        
        if share.seed_checksum != first_seed_checksum:
            raise ChecksumError(
                Checksum.ShareGroup, first_seed_checksum, share.seed_checksum
            )

    if len(shares) < shares[0].threshold:
        raise ThresholdError(shares[0].threshold, len(shares))

    # Recover mnemonic seed with Lagrange interpolation.
    share_points = [share.point for share in shares]

    orignal_key = Lagrange.interpolate(share_points, PRIME_MODULUS, 0)
    original_hash_int = Lagrange.interpolate(share_points, PRIME_MODULUS, 1)
    original_hash = original_hash_int.to_bytes(32, "big")
    recalculated_hash = Encode.mnemonic_hash(orignal_key)

    if original_hash != recalculated_hash:
        raise ChecksumError(
            Checksum.KeyValue, original_hash, recalculated_hash
        )

    mnemonic = Mnemonic()
    mnemonic.seed = orignal_key.to_bytes(32, "big")
    mnemonic.checksum = original_hash[:1]

    return mnemonic


def get_phrase(
        mnemonic_or_share: Mnemonic | Share, language: Language
        ) -> List[str]:
    """
    Returns a list of words represending a mnemonic phrase or a share phrase,
    based on the type of the given object.
    """
    if isinstance(mnemonic_or_share, Mnemonic):
        return [mnemonic_or_share.get_word(i, language) for i in range(24)]
    elif isinstance(mnemonic_or_share, Share):
        return [mnemonic_or_share.get_word(i, language) for i in range(27)]
    else:
        message = "The given mnemonic_or_share argument was not of the type \
            Mnemonic or Share."
        raise TypeError(message)
