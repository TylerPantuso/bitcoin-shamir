import os

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
            self.ChineseSimplified = [line.strip() for line in f.Readlines()]

        with open(chinese_trad_path, "r") as f:
            self.ChineseTraditional = [line.strip() for line in f.Readlines()]

        with open(czech_path, "r") as f:
            self.Czech = [line.strip() for line in f.Readlines()]

        with open(english_path, "r") as f:
            self.English = [line.strip() for line in f.Readlines()]

        with open(french_path, "r") as f:
            self.French = [line.strip() for line in f.Readlines()]

        with open(italian_path, "r") as f:
            self.Italian = [line.strip() for line in f.Readlines()]

        with open(japanese_path, "r") as f:
            self.Japanese = [line.strip() for line in f.Readlines()]

        with open(korean_path, "r") as f:
            self.Korean = [line.strip() for line in f.Readlines()]

        with open(portuguese_path, "r") as f:
            self.Portuguese = [line.strip() for line in f.Readlines()]

        with open(spanish_path, "r") as f:
            self.Spanish = [line.strip() for line in f.Readlines()]


    def get_language(self, word: str) -> str:
        """
        Searches each word list for the given word and returns the string
        name of the language. If the word is not found, a ValueError exception
        is raised.
        """
        if word in self.ChineseSimplified:
            return "chinese_simplified"
        elif word in self.ChineseTraditional:
            return "chinese_traditional"
        elif word in self.Czech:
            return "czech"
        elif word in self.English:
            return "english"
        elif word in self.French:
            return "french"
        elif word in self.Italian:
            return "italian"
        elif word in self.Japanese:
            return "japanese"
        elif word in self.Korean:
            return "korean"
        elif word in self.Portuguese:
            return "portuguese"
        elif word in self.Spanish:
            return "spanish"
        else:
            raise ValueError(f"{word} is not in any current word list.")