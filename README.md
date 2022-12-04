BitcoinShamir 1.0.1


pip install bitcoinshamir


Description:
A pure python implementation of the Shamir Secret Sharing scheme for use with
BIP-39 mnemonic codes. Split a 24-word mnemonic phrase into several shares,
and set a minimum threshold to recover your original phrase.

Code Example:
>>> from bitcoinshamir import *
>>> 
>>> # Generate a random mnemonic phrase.
>>> mnemonic = Mnemonic.generate_random()
>>> mnemonic_phrase = get_phrase(mnemonic, Language.English)
>>> 
>>> # Create a 3 of 5 sharing scheme, for which any 3 shares can recover the
>>> # original mnemonic phrase.
>>> shares = create_shares(3, 5, mnemonic)
>>> 
>>> # Write down each share phrase and pass out to participants.
>>> phrase_1 = get_phrase(shares[0], Language.English)
>>> phrase_2 = get_phrase(shares[1], Language.English)
>>> phrase_3 = get_phrase(shares[2], Language.English)
>>> phrase_4 = get_phrase(shares[3], Language.English)
>>> phrase_5 = get_phrase(shares[4], Language.English)
>>> 
>>> # The original mnemonic phrase can be recovered with any three of the share
>>> # phrases.
>>> recovery_share_1 = Share.from_share_phrase(phrase_4, Language.English)
>>> recovery_share_2 = Share.from_share_phrase(phrase_2, Language.English)
>>> recovery_share_3 = Share.from_share_phrase(phrase_5, Language.English)
>>> recovery_shares = [recovery_share_1, recovery_share_2, recovery_share_3]
>>> 
>>> recovered_mnemonic = recover_mnemonic(recovery_shares)
>>> recovered_phrase = get_phrase(recovered_mnemonic, Language.English)
>>>
>>> # You can also use recovery shares to generate new shares.
>>> recovery_points = [share.point for share in recovery_shares]
>>> X = 7
>>> Y = Lagrange.interpolate(recovery_points, PRIME_MODULUS, X)
>>> point = Point(X, Y)
>>> threshold = recovery_shares[0].threshold
>>> seed_checksum = recovery_shares[0].seed_checksum
>>> 
>>> share_6 = Share(point, threshold, seed_checksum)
>>> 
>>> # You can change the language of your share phrase or mnemonic phrase.
>>> mnemonic = Mnemonic()
>>> english_phrase = ["team", "lend", "rice"] # Set this to your actual phrase
>>> 
>>> for i, word in enumerate(english_phrase):
>>>     mnemonic.set_word(i, word, Language.English)
>>> 
>>> spanish_phrase = get_phrase(mnemonic, Language.Spanish)
>>> italian_phrase = get_phrase(mnemonic, Language.Italian)
>>> korean_phrase = get_phrase(mnemonic, Language.Korean)
>>> 

Notes:
 - You must have the minimum threshold shares to recover your original phrase.
 - Even 1 less share will not reveal a single word from the original phrase.
 - Using more shares than the threshold will still recover the original phrase.
 - Share phrases use the same BIP-39 word lists as mnemonic phrases do.
 - Each share has a checksum, which will raise an error for any miskeyed words.
 - Each share uses the original mnemonic checksum as a group ID.
 - Shares do not need to be in the same language. They are not stored as text.

Share Construction:
Each share represents an (X, Y) coordinate on a graph. It is 37 bytes, in order
of the following:
   32 bytes - The Y-value of the share
   1 byte - The original mnemonic's checksum
   5 bits - The version, xor the share checksum
   4 bits - The threshold, xor the share checksum
   7 bits - The X-value, xor the share checksum
   2 bytes - The share checksum

The version, threshold, and X-value are all concatenated and applied the xor of
the share checksum at the same time. The share checksum is the first 2 bytes of
the sha256 hash of the first 35 bytes.