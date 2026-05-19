from __future__ import annotations
import re
from dataclasses import dataclass

_QWERTY_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

_QWERTY_GRAPH: dict[str, set[str]] = {}
for _row in _QWERTY_ROWS:
    for _i, _ch in enumerate(_row):
        nb = set()
        if _i > 0:             nb.add(_row[_i - 1])
        if _i < len(_row) - 1: nb.add(_row[_i + 1])
        _QWERTY_GRAPH.setdefault(_ch, set()).update(nb)
        _QWERTY_GRAPH.setdefault(_ch.upper(), set()).update(n.upper() for n in nb)


@dataclass
class Finding:
    name: str
    description: str
    matched: str
    severity: float
    penalty_bits: float


def _detect_repeats(pw: str) -> list[Finding]:
    findings = []
    for m in re.finditer(r'(.)\1{2,}', pw):
        run = m.group()
        sev = min(0.9, 0.3 + 0.1 * len(run))
        findings.append(Finding(
            name="repeated_chars",
            description=f"Repeated character run: '{run}'",
            matched=run,
            severity=sev,
            penalty_bits=round(len(run) * 0.5, 1),
        ))
    return findings


def _detect_sequences(pw: str) -> list[Finding]:
    findings = []
    pw_lower = pw.lower()
    seq_len = 1
    direction = 0
    seq_start = 0

    def _flush(start: int, end: int, d: int) -> None:
        seq = pw_lower[start:end]
        if len(seq) >= 3:
            label = "ascending" if d == 1 else "descending"
            sev = min(0.85, 0.25 + 0.1 * len(seq))
            findings.append(Finding(
                name="sequence",
                description=f"Character sequence ({label}): '{seq}'",
                matched=pw[start:end],
                severity=sev,
                penalty_bits=round(len(seq) * 0.8, 1),
            ))

    for i in range(1, len(pw_lower)):
        delta = ord(pw_lower[i]) - ord(pw_lower[i - 1])
        if delta in (1, -1):
            if direction == 0 or direction == delta:
                direction = delta
                seq_len += 1
                continue
        _flush(seq_start, seq_start + seq_len, direction)
        seq_start = i
        seq_len = 1
        direction = 0

    _flush(seq_start, seq_start + seq_len, direction)
    return findings


def _detect_keyboard_walks(pw: str, min_len: int = 4) -> list[Finding]:
    findings = []
    pw_lower = pw.lower()
    walk_start = 0
    walk_len = 1

    def _flush(start: int, end: int) -> None:
        if end - start >= min_len:
            matched = pw[start:end]
            sev = min(0.9, 0.3 + 0.1 * (end - start))
            findings.append(Finding(
                name="keyboard_walk",
                description=f"Keyboard walk detected: '{matched}'",
                matched=matched,
                severity=sev,
                penalty_bits=round((end - start) * 1.5, 1),
            ))

    for i in range(1, len(pw_lower)):
        if pw_lower[i] in _QWERTY_GRAPH.get(pw_lower[i - 1], set()):
            walk_len += 1
        else:
            _flush(walk_start, walk_start + walk_len)
            walk_start = i
            walk_len = 1

    _flush(walk_start, walk_start + walk_len)
    return findings


_LEET: dict[str, str] = {
    '@': 'a', '4': 'a', '8': 'b', '(': 'c', '3': 'e',
    '6': 'g', '1': 'i', '!': 'i', '0': 'o', '5': 's',
    '$': 's', '+': 't', '7': 't', '2': 'z',
}

def _deleet(pw: str) -> str:
    return ''.join(_LEET.get(c, c) for c in pw.lower())


def _detect_dictionary(pw: str, wordlist: set[str], min_word: int = 4) -> list[Finding]:
    findings = []
    pw_lower  = pw.lower()
    pw_deleet = _deleet(pw)
    checked: set[str] = set()

    for word in wordlist:
        if len(word) < min_word:
            continue
        for variant in (pw_lower, pw_deleet):
            if word in variant and word not in checked:
                checked.add(word)
                sev = min(0.95, 0.4 + 0.05 * len(word))
                findings.append(Finding(
                    name="dictionary_word",
                    description=f"Dictionary word found: '{word}'",
                    matched=word,
                    severity=sev,
                    penalty_bits=round(len(word) * 2.0, 1),
                ))
                break

    return findings


def analyse(password: str, wordlist: set[str] | None = None) -> list[Finding]:
    results: list[Finding] = []
    results.extend(_detect_repeats(password))
    results.extend(_detect_sequences(password))
    results.extend(_detect_keyboard_walks(password))
    if wordlist:
        results.extend(_detect_dictionary(password, wordlist))
    results.sort(key=lambda f: f.severity, reverse=True)
    return results