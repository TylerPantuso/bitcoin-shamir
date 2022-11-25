import os
from typing import List

class BIP39_List:
    """
    BIP39_List class for loading BIP39 word lists.
    """
    LANGUAGE_LIST = [
        "chinese_simplified",
        "chinese_traditional",
        "czech",
        "english",
        "french",
        "italian",
        "japanese",
        "korean",
        "portuguese",
        "spanish"
    ]

    def __init__(self) -> None:
        """
        Creates a new BIP39_List class, and loads the word lists from the
        WordLists directory.
        """
        folder = os.path.join(os.path.dirname(__file__), "WordLists")

        chinese_simp_path = os.path.join(folder, "chinese_simplified.txt")
        chinese_trad_path = os.path.join(folder, "chinese_traditional.txt")
        czech_path = os.path.join(folder, "czech.txt")
        english_path = os.path.join(folder, "english.txt")
        french_path = os.path.join(folder, "french.txt")
        italian_path = os.path.join(folder, "italian.txt")
        japanese_path = os.path.join(folder, "japanese.txt")
        korean_path = os.path.join(folder, "korean.txt")
        portuguese_path = os.path.join(folder, "portuguese.txt")
        spanish_path = os.path.join(folder, "spanish.txt")

        with open(chinese_simp_path, "r") as f:
            self.ChineseSimplified = [line.strip() for line in f.readlines()]

        with open(chinese_trad_path, "r") as f:
            self.ChineseTraditional = [line.strip() for line in f.readlines()]

        with open(czech_path, "r") as f:
            self.Czech = [line.strip() for line in f.readlines()]

        with open(english_path, "r") as f:
            self.English = [line.strip() for line in f.readlines()]

        with open(french_path, "r") as f:
            self.French = [line.strip() for line in f.readlines()]

        with open(italian_path, "r") as f:
            self.Italian = [line.strip() for line in f.readlines()]

        with open(japanese_path, "r") as f:
            self.Japanese = [line.strip() for line in f.readlines()]

        with open(korean_path, "r") as f:
            self.Korean = [line.strip() for line in f.readlines()]

        with open(portuguese_path, "r") as f:
            self.Portuguese = [line.strip() for line in f.readlines()]

        with open(spanish_path, "r") as f:
            self.Spanish = [line.strip() for line in f.readlines()]


    def get_language(self, word: str) -> List[str]:
        """
        Searches each word list for the given word and returns the string
        name of each language that contains the given word.
        """
        languages = []

        if word in self.ChineseSimplified:
            languages.append("chinese_simplified")

        if word in self.ChineseTraditional:
            languages.append("chinese_traditional")

        if word in self.Czech:
            languages.append("czech")

        if word in self.English:
            languages.append("english")

        if word in self.French:
            languages.append("french")

        if word in self.Italian:
            languages.append("italian")

        if word in self.Japanese:
            languages.append("japanese")

        if word in self.Korean:
            languages.append("korean")

        if word in self.Portuguese:
            languages.append("portuguese")

        if word in self.Spanish:
            languages.append("spanish")

        return languages