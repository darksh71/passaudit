from __future__ import annotations
from dataclasses import dataclass

from . import entropy as _entropy
from . import patterns as _patterns
from . import hibp as _hibp


@dataclass
class PasswordReport:
    password: str
    entropy: _entropy.EntropyResult
    findings: list[_patterns.Finding]
    hibp: _hibp.HIBPResult
    score: int
    grade: str
    verdict: str


def _compute_score(
    ent: _entropy.EntropyResult,
    findings: list[_patterns.Finding],
    hibp_result: _hibp.HIBPResult,
) -> int:
    pool_score    = min(50, int(ent.pool_bits / 60 * 50))
    bits_per_char = ent.shannon_bits / ent.length if ent.length else 0
    shannon_score = min(20, int(bits_per_char / 3.5 * 20))
    length_score  = min(15, int((ent.length - 4) * 1.5)) if ent.length > 4 else 0

    penalty = min(40, sum(int(f.penalty_bits * 1.5) for f in findings))
    breach_penalty = 50 if (hibp_result.checked and hibp_result.pwned) else 0

    return max(0, min(100, pool_score + shannon_score + length_score - penalty - breach_penalty))


def _grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 75: return "A"
    if score >= 60: return "B"
    if score >= 45: return "C"
    if score >= 30: return "D"
    return "F"


def _verdict(score: int, hibp: _hibp.HIBPResult) -> str:
    if hibp.checked and hibp.pwned:
        return f"⛔  Compromised — found {hibp.count:,} times in breach data. Change immediately."
    if score >= 90: return "✅  Excellent — strong entropy, no detectable patterns."
    if score >= 75: return "✅  Good — minor improvements possible."
    if score >= 60: return "⚠️   Fair — consider lengthening or diversifying character types."
    if score >= 45: return "⚠️   Weak — significant patterns detected or low entropy."
    if score >= 30: return "❌  Poor — easily guessable."
    return "❌  Very poor — do not use this password."


def analyse(
    password: str,
    wordlist: set[str] | None = None,
    skip_hibp: bool = False,
) -> PasswordReport:
    ent      = _entropy.analyse(password)
    findings = _patterns.analyse(password, wordlist=wordlist)
    hibp_res = (
        _hibp.HIBPResult(checked=False, pwned=False, count=0, sha1_prefix="")
        if skip_hibp else _hibp.check(password)
    )
    score = _compute_score(ent, findings, hibp_res)
    return PasswordReport(
        password=password,
        entropy=ent,
        findings=findings,
        hibp=hibp_res,
        score=score,
        grade=_grade(score),
        verdict=_verdict(score, hibp_res),
    )