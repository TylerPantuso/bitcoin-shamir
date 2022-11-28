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
        Searches each word list for the given word and returns the string name
        of each language that contains the given word. If the word is not
        contained in any of the word lists, an empty list is returned.
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


    def get_word_list(self, language: str) -> List[str]:
        """
        Returns the word list based on the given language. Raises an error if
        the given language is not in the current language list.
        """
        if language == "chinese_simplified":
            return self.ChineseSimplified
        elif language == "chinese_traditional":
            return self.ChineseTraditional
        elif language == "czech":
            return self.Czech
        elif language == "english":
            return self.English
        elif language == "french":
            return self.French
        elif language == "italian":
            return self.Italian
        elif language == "japanese":
            return self.Japanese
        elif language == "korean":
            return self.Korean
        elif language == "portuguese":
            return self.Portuguese
        elif language == "spanish":
            return self.Spanish
        else:
            raise ValueError(f"{language} is not in the current language list.")


    def get_word(self, language: str, index: int) -> str:
        """
        Gets the word based on the given language and zero-based index of the
        word. Raises an error if the language is not in the current language
        list or if the index is out of bounds.
        """
        if language not in self.LANGUAGE_LIST:
            raise ValueError(f"{language} is not in the current language list.")

        if not isinstance(index, int):
            raise TypeError("The given index argument was not of type int.")

        if index > 2047 or index < 0:
            raise IndexError(f"The index, {index}, is out of range.")

        return self.get_word_list(language)[index]


    def get_word_index(self, language: str, word: str) -> int:
        """
        Gets the index of the given word from the given language. Raises an
        error if the language is not in the current language list or if the word
        does not exist within the given language's word list.
        """
        if language not in self.LANGUAGE_LIST:
            raise ValueError(f"{language} is not in the current language list.")

        if language not in self.get_language(word):
            raise ValueError(f"{word} not in the {language} word list.")

        return self.get_word_list(language).index(word)
        