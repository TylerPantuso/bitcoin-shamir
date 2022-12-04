import os
from typing import List
from .enums import Language
from .exceptions import WordlistError

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

        with open(chinese_simp_path, "r", encoding="utf-8") as f:
            self.ChineseSimplified = [line.strip() for line in f.readlines()]

        with open(chinese_trad_path, "r", encoding="utf-8") as f:
            self.ChineseTraditional = [line.strip() for line in f.readlines()]

        with open(czech_path, "r", encoding="utf-8") as f:
            self.Czech = [line.strip() for line in f.readlines()]

        with open(english_path, "r", encoding="utf-8") as f:
            self.English = [line.strip() for line in f.readlines()]

        with open(french_path, "r", encoding="utf-8") as f:
            self.French = [line.strip() for line in f.readlines()]

        with open(italian_path, "r", encoding="utf-8") as f:
            self.Italian = [line.strip() for line in f.readlines()]

        with open(japanese_path, "r", encoding="utf-8") as f:
            self.Japanese = [line.strip() for line in f.readlines()]

        with open(korean_path, "r", encoding="utf-8") as f:
            self.Korean = [line.strip() for line in f.readlines()]

        with open(portuguese_path, "r", encoding="utf-8") as f:
            self.Portuguese = [line.strip() for line in f.readlines()]

        with open(spanish_path, "r", encoding="utf-8") as f:
            self.Spanish = [line.strip() for line in f.readlines()]


    def get_language(self, word: str) -> List[Language]:
        """
        Searches each word list for the given word and returns the string name
        of each language that contains the given word. If the word is not
        contained in any of the word lists, an empty list is returned.
        """
        languages = []

        if word in self.ChineseSimplified:
            languages.append(Language.ChineseSimplified)

        if word in self.ChineseTraditional:
            languages.append(Language.ChineseTraditional)

        if word in self.Czech:
            languages.append(Language.Czech)

        if word in self.English:
            languages.append(Language.English)

        if word in self.French:
            languages.append(Language.French)

        if word in self.Italian:
            languages.append(Language.Italian)

        if word in self.Japanese:
            languages.append(Language.Japanese)

        if word in self.Korean:
            languages.append(Language.Korean)

        if word in self.Portuguese:
            languages.append(Language.Portuguese)

        if word in self.Spanish:
            languages.append(Language.Spanish)

        return languages


    def get_word_list(self, language: Language) -> List[str]:
        """
        Returns the word list based on the given language.
        """
        if language == Language.ChineseSimplified:
            return self.ChineseSimplified
        elif language == Language.ChineseTraditional:
            return self.ChineseTraditional
        elif language == Language.Czech:
            return self.Czech
        elif language == Language.English:
            return self.English
        elif language == Language.French:
            return self.French
        elif language == Language.Italian:
            return self.Italian
        elif language == Language.Japanese:
            return self.Japanese
        elif language == Language.Korean:
            return self.Korean
        elif language == Language.Portuguese:
            return self.Portuguese
        elif language == Language.Spanish:
            return self.Spanish
        else:
            raise ValueError(f"{language} is not in the language list.")


    def get_word(self, index: str, language: Language) -> str:
        """
        Gets the word based on the given index and language.
        """
        if not isinstance(language, Language):
            raise ValueError(f"{language} is not in the language list.")

        if not isinstance(index, int):
            raise TypeError("The given index argument was not of type int.")

        if index > 2047 or index < 0:
            raise IndexError(f"The index, {index}, is out of range.")

        return self.get_word_list(language)[index]


    def get_word_index(self, word: str, language: Language) -> int:
        """
        Gets the index of the given word from the given language.
        """
        if not isinstance(language, Language):
            raise ValueError(f"{language} is not in the language list.")

        if language not in self.get_language(word):
            raise WordlistError(word, language)

        return self.get_word_list(language).index(word)
        