# passaudit

A CLI tool for evaluating password strength and auditing credential security. Goes beyond surface-level checks — entropy calculation, structural pattern detection, and breach database lookups via the HaveIBeenPwned k-anonymity API.

```
$ passaudit check "hunter2" --no-hibp

  Password               *******
  Length                 7 characters
  Character pools        digits, lowercase (pool size: 36)
  Pool entropy           36.2 bits
  Shannon entropy        19.6 bits
  Crack time (est.)      less than a minute

  Score  █████████░░░░░░░░░░░░░░░░░░░░░  32/100  [D]

  ❌  Poor — easily guessable.

  Patterns detected
    [HIGH  ] Dictionary word found: 'hunter'
```

---

## Installation

```bash
git clone https://github.com/yourname/passaudit
cd passaudit
pip install -r requirements.txt
```

No external dependencies beyond `requests`. Python 3.11+.

---

## Usage

### Checking a password

```bash
# Basic check (includes HIBP breach lookup)
python cli.py check "MyP@ssw0rd!"

# Multiple passwords
python cli.py check "password1" "P@55w0rd" "correct-horse-battery"

# Offline mode (skip HIBP network call)
python cli.py check "MyPassword" --no-hibp

# With a custom wordlist for dictionary checks
python cli.py check "acmecorp2024" --wordlist /usr/share/dict/words

# JSON output (useful for scripting)
python cli.py check "hunter2" --no-hibp --json

# Read passwords from stdin (e.g. a leaked list)
cat passwords.txt | python cli.py check --stdin --no-hibp --json
```

### Generating a candidate wordlist

```bash
# Basic wordlist from seed words
python cli.py wordlist acme corp --output candidates.txt

# Target-specific wordlist for a red-team engagement
python cli.py wordlist john smith 1985 fluffy --output john_candidates.txt

# Control the output
python cli.py wordlist target \
  --no-leet \           # skip l33t substitutions
  --no-combinations \   # don't combine words
  --min-length 8 \      # enforce policy minimum
  --max-length 20 \
  --output out.txt
```

---

## What it measures

### 1. Entropy

Two complementary measures:

**Pool entropy** — `log2(pool_size ^ length)`. Measures the theoretical brute-force search space. A password with 60 bits of pool entropy means an attacker must try up to 2⁶⁰ guesses — about 70 minutes at 1 billion guesses/second.

**Shannon entropy** — `-Σ p(c) log2 p(c)` over character frequency. Measures how uniformly the characters are distributed. `aaaaaaaaa` has high pool entropy but near-zero Shannon entropy because it's entirely predictable once you know one character.

### 2. Pattern detection

Four detector categories:

| Pattern | Example | Effect |
|---|---|---|
| Repeated chars | `aaaa`, `1111` | Drastically reduces effective entropy |
| Sequences | `abcd`, `9876` | Predictable, covers tiny search space |
| Keyboard walks | `qwerty`, `asdf` | Extremely common in breach data |
| Dictionary words | `hunter`, `dragon` | Matched with and without leet substitution |

### 3. Breach check (HIBP k-anonymity)

Checks the password against 900M+ compromised passwords without sending the password to any server. See the deep-dive below.

---

## Scoring

| Range | Grade | Meaning |
|---|---|---|
| 90–100 | A+ | Strong — production ready |
| 75–89  | A  | Good — minor improvements possible |
| 60–74  | B  | Fair — consider longer or more complex |
| 45–59  | C  | Weak — patterns detected or low entropy |
| 30–44  | D  | Poor — easily guessable |
| 0–29   | F  | Do not use |

Breach database hit immediately caps score at 50 regardless of other factors.

---

## How k-anonymity works with the HIBP API

> This is the section worth understanding for interviews.

### The naive approach (bad)

The obvious way to check if a password has been breached: send it to a server that has a list of breached passwords and ask "is this in your list?" This works, but it means the server now knows your exact password. Even over HTTPS, you're trusting the operator.

### Hashing (better, still not great)

Send the SHA-1 hash of the password instead. The server has a list of hashes — yours is either there or it isn't. Better, but the hash of a common password like `password` is always the same (`5baa61e4...`). A determined server operator or network observer could correlate your hash against a pre-computed rainbow table.

### k-Anonymity (what HIBP actually does)

k-anonymity is a formal privacy model: a query is `k`-anonymous if at least `k-1` other people make an indistinguishable query. HIBP achieves this through prefix bucketing:

1. **Client** computes `SHA1("hunter2")` → `F3BBBD66A63D4BF1747940578EC3D0103530E21D`
2. **Client** sends only the first 5 hex characters: `F3BBB`
3. **HIBP server** returns all ~500 hashes that share that prefix — a bucket
4. **Client** searches locally for its full suffix (`D66A63D4BF1747940578EC3D0103530E21D`)

The server sees `F3BBB` — but so do all other users whose password hashes start with those characters. There's no way for the server to know which specific hash the client was interested in. The password never leaves the machine.

```
Client                          HIBP Server
  |                                  |
  |  SHA1("hunter2") = F3BBBD66...   |
  |                                  |
  |  GET /range/F3BBB  ─────────────>|
  |                                  |  (server sees only the prefix)
  |  <──── 500 hash suffixes ──────  |
  |                                  |
  |  Scan locally for D66A63...      |
  |  Found! Count = 17,043           |
  |                                  |
```

The "Add-Padding" header (which passaudit sends) is an additional mitigation: the server pads responses to a uniform size, preventing an adversary from inferring the bucket size from network packet size — a traffic-analysis side channel.

#### Why 5 characters?

With SHA-1 producing 40 hex characters (160 bits), the first 5 characters give 16⁵ = 1,048,576 possible prefixes. HIBP's ~900M entries average ~857 entries per bucket — enough to provide strong anonymity without making the response payloads impractically large.

---

## Wordlist generation

The `wordlist` subcommand builds candidate password lists by applying transformations to seed words:

- **Leet substitutions**: `a→@/4`, `e→3`, `i→1/!`, `o→0`, `s→$/5` (up to 2 simultaneous substitutions per word to keep output tractable)
- **Case variants**: lowercase, UPPERCASE, Capitalised, Title Case
- **Affix mutations**: common prefixes (`the`, `my`, `Mr`) × common suffixes (`123`, `2024`, `!`, `007`, …)
- **Reversed words**: `acme` → `emca`
- **Combinations**: all permutations of seed word pairs (and triples with `--max-combo 3`)

Two seed words typically produce 10,000–20,000 candidates. This is useful for:

- Testing account lockout thresholds (never run against accounts you don't own)
- Auditing whether a user's chosen password is derivable from known personal context
- CTF and lab environments

---

## Project structure

```
passaudit/
├── passaudit/
│   ├── __init__.py       # package init, bundled wordlist loader
│   ├── analyzer.py       # orchestrates everything into a PasswordReport
│   ├── entropy.py        # Shannon + pool entropy, crack-time estimation
│   ├── patterns.py       # keyboard walks, sequences, repeats, dictionary
│   ├── hibp.py           # k-anonymity HIBP API client
│   ├── wordlist.py       # candidate password list generator
│   └── data/
│       └── common_words.txt
├── cli.py                # argparse entry point
├── requirements.txt
└── pyproject.toml
```

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All passwords scored ≥ 45 |
| 1 | No passwords provided / argument error |
| 2 | One or more passwords scored < 45 (useful in CI/pre-commit hooks) |

---

## Limitations

- Crack-time estimates assume offline attacks at 10¹⁰ guesses/second (a reasonable mid-range for fast hash functions like MD5/SHA-1). Against bcrypt or Argon2, real-world times are orders of magnitude longer.
- The bundled wordlist is intentionally small. For thorough dictionary checks, pass `/usr/share/dict/words` or a SecLists wordlist with `--wordlist`.
- HIBP checks require an internet connection and are rate-limited. Use `--no-hibp` for bulk offline analysis.
