from __future__ import annotations
import itertools
from typing import Generator

_LEET_MAP: dict[str, list[str]] = {
    'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'],
    'o': ['0'], 's': ['$', '5'], 't': ['+', '7'],
    'l': ['1'], 'g': ['9'], 'b': ['8'],
}

_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345",
    "!", "!!", "!1", "123!", "2024", "2025",
    "#1", "*", "0", "00", "007",
]

_PREFIXES = ["", "the", "my", "Mr", "Mrs", "Dr"]

_CASE_FNS = [
    str.lower, str.upper, str.capitalize, str.title,
    lambda w: w[0].upper() + w[1:].lower() if w else w,
]


def _case_variants(word: str) -> Generator[str, None, None]:
    seen: set[str] = set()
    for fn in _CASE_FNS:
        v = fn(word)
        if v not in seen:
            seen.add(v)
            yield v


def _leet_variants(word: str, max_subs: int = 2) -> Generator[str, None, None]:
    positions = [(i, ch) for i, ch in enumerate(word.lower()) if ch in _LEET_MAP]
    seen: set[str] = set()

    if word not in seen:
        seen.add(word)
        yield word

    for r in range(1, min(max_subs, len(positions)) + 1):
        for combo in itertools.combinations(positions, r):
            chars = list(word)
            opts = [_LEET_MAP[ch] for _, ch in combo]
            for sub_set in itertools.product(*opts):
                for (idx, _), sub in zip(combo, sub_set):
                    chars[idx] = sub
                v = "".join(chars)
                if v not in seen:
                    seen.add(v)
                    yield v


def _affix_variants(word: str) -> Generator[str, None, None]:
    for pre in _PREFIXES:
        for suf in _SUFFIXES:
            yield f"{pre}{word}{suf}"


def generate(
    base_words: list[str],
    *,
    include_leet: bool = True,
    include_affixes: bool = True,
    include_reversed: bool = True,
    include_combinations: bool = True,
    max_combinations: int = 2,
    deduplicate: bool = True,
) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def _emit(word: str) -> None:
        if not deduplicate or word not in seen:
            seen.add(word)
            candidates.append(word)

    all_words = list(base_words)
    if include_combinations and len(base_words) > 1:
        for r in range(2, min(max_combinations + 1, len(base_words) + 1)):
            for combo in itertools.permutations(base_words, r):
                all_words.append("".join(combo))

    for word in all_words:
        variants = [word, word[::-1]] if include_reversed else [word]
        for w in variants:
            for case_v in _case_variants(w):
                leet_src = list(_leet_variants(case_v)) if include_leet else [case_v]
                for leet_v in leet_src:
                    if include_affixes:
                        for affixed in _affix_variants(leet_v):
                            _emit(affixed)
                    else:
                        _emit(leet_v)

    return candidates


def write_wordlist(
    candidates: list[str],
    output_path: str,
    min_length: int = 6,
    max_length: int = 64,
) -> int:
    written = 0
    with open(output_path, "w", encoding="utf-8") as fh:
        for word in candidates:
            if min_length <= len(word) <= max_length:
                fh.write(word + "\n")
                written += 1
    return written