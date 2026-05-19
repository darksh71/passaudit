import math
import string
from dataclasses import dataclass

_POOLS = [
    ("digits",     string.digits,          10),
    ("lowercase",  string.ascii_lowercase, 26),
    ("uppercase",  string.ascii_uppercase, 26),
    ("symbols",    string.punctuation,     32),
]


@dataclass
class EntropyResult:
    shannon_bits: float
    pool_bits: float
    pool_size: int
    pool_names: list[str]
    length: int


def analyse(password: str) -> EntropyResult:
    if not password:
        return EntropyResult(0.0, 0.0, 0, [], 0)

    freq: dict[str, int] = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1

    length = len(password)
    shannon = -sum(
        (c / length) * math.log2(c / length)
        for c in freq.values() if c > 0
    )
    shannon_bits = shannon * length

    active_pools = []
    pool_size = 0
    pw_set = set(password)
    for name, chars, size in _POOLS:
        if pw_set & set(chars):
            active_pools.append(name)
            pool_size += size

    pool_bits = length * math.log2(pool_size) if pool_size > 1 else 0.0

    return EntropyResult(
        shannon_bits=round(shannon_bits, 2),
        pool_bits=round(pool_bits, 2),
        pool_size=pool_size,
        pool_names=active_pools,
        length=length,
    )


def crack_time_label(pool_bits: float) -> str:
    if pool_bits == 0:
        return "instant"

    # assuming ~10B guesses/sec (fast hash offline attack)
    seconds = (2 ** pool_bits) / 1e10
    thresholds = [
        (60,                  "less than a minute"),
        (3_600,               "minutes"),
        (86_400,              "hours"),
        (86_400 * 30,         "days"),
        (86_400 * 365,        "months"),
        (86_400 * 365 * 100,  "years"),
        (86_400 * 365 * 1e6,  "centuries"),
    ]
    for limit, label in thresholds:
        if seconds < limit:
            return label
    return "millions of years"