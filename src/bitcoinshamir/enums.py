from enum import Enum


class Language(str, Enum):
    ChineseSimplified = "chinese_simplified"
    ChineseTraditional = "chinese_traditional"
    Czech = "czech"
    English = "english"
    French = "french"
    Italian = "italian"
    Japanese = "japanese"
    Korean = "korean"
    Portuguese = "portuguese"
    Spanish = "spanish"


class Checksum(str, Enum):
    Mnemonic = "Mnemonic 8-bit Checksum"
    KeyValue = "Mnemonic 32-byte Checksum"
    ShareGroup = "Share Group 8-bit Checksum"
    Share = "Share Key 16-bit Checksum"