# passaudit

A CLI tool for auditing password strength. Calculates entropy, detects structural patterns, and checks against 900M+ breached passwords using the HaveIBeenPwned API — without ever sending your password over the network.

```
$ python cli.py check "hunter2"

  Password               *******
  Length                 7 characters
  Character pools        digits, lowercase (pool size: 36)
  Pool entropy           36.2 bits
  Shannon entropy        19.6 bits
  Crack time (est.)      less than a minute

  Score  █████████░░░░░░░░░░░░░░░░░░░░░  32/100  [D]

  ❌  Poor — easily guessable.

  HIBP check       ⛔  YES — seen 65,744× in breach databases

  Patterns detected
    [HIGH  ] Dictionary word found: 'hunter'
```

---

## Installation

```bash
git clone https://github.com/darksh71/passaudit.git
cd passaudit
python -m pip install requests
```

Python 3.11+ required.

---

## Usage

### Check a password

```bash
# Full check including breach lookup
python cli.py check "MyPassword123"

# Multiple passwords at once
python cli.py check "password1" "Tr0ub4dor&3" "correcthorsebatterystaple"

# Offline mode — skips HIBP network call
python cli.py check "MyPassword" --no-hibp

# Custom wordlist for dictionary checks
python cli.py check "acmecorp2024" --wordlist /usr/share/dict/words

# JSON output for scripting
python cli.py check "hunter2" --json

# Read from stdin
cat passwords.txt | python cli.py check --stdin --no-hibp
```

### Generate a candidate wordlist

```bash
# Basic wordlist from seed words
python cli.py wordlist acme corp --output candidates.txt

# Control mutations
python cli.py wordlist john smith 1990 \
  --min-length 8 \
  --max-length 20 \
  --no-leet \
  --output out.txt
```

---

## How it works

### Entropy

Two measures are calculated for each password:

**Pool entropy** — `log2(pool_size ^ length)`. The theoretical brute-force search space based on which character types are present. 60 bits at 10 billion guesses/second takes around 36 years.

**Shannon entropy** — measures character distribution uniformity. `aaaaaaaaa` has high pool entropy but near-zero Shannon entropy — once you know one character, you know them all.

### Pattern detection

| Pattern | Example | Impact |
|---|---|---|
| Keyboard walk | `qwerty`, `asdf` | High |
| Character sequence | `abcd`, `9876` | High |
| Repeated chars | `aaaa`, `1111` | Medium |
| Dictionary word | `hunter`, `dragon` | High |

Dictionary checks run against both the raw password and leet-substituted variants (`h4ck3r` → `hacker`).

### Breach check — k-anonymity

The HIBP lookup never sends your password or its full hash anywhere:

1. SHA-1 hash your password locally → `F3BBBD66A63D4BF1747940578EC3D0103530E21D`
2. Send only the first 5 characters → `F3BBB`
3. HIBP returns ~500 hash suffixes that share that prefix
4. Search the response locally for your suffix → found/not found

The server sees a 5-character prefix shared by hundreds of other users. It has no way to know which specific password was being checked.

### Scoring

| Score | Grade | |
|---|---|---|
| 90–100 | A+ | Strong |
| 75–89 | A | Good |
| 60–74 | B | Fair |
| 45–59 | C | Weak |
| 30–44 | D | Poor |
| 0–29 | F | Very poor |

A breach database hit caps the score at 50 regardless of entropy.

### Wordlist generation

Applies the following mutations to seed words:
- Leet substitutions (`a→@/4`, `e→3`, `o→0`, up to 2 simultaneous)
- Case variants (lower, UPPER, Capitalised, Title)
- Common prefix/suffix combinations (`123`, `2024`, `!`, `007`, …)
- Reversed words
- Multi-word combinations and permutations

Two seed words typically produces ~15,000 candidates.

---

## Project structure

```
passaudit/
├── passaudit/
│   ├── __init__.py
│   ├── analyzer.py     # orchestrates report generation
│   ├── entropy.py      # Shannon + pool entropy calculation
│   ├── patterns.py     # keyboard walk, sequence, repeat, dictionary detection
│   ├── hibp.py         # k-anonymity HIBP API client
│   ├── wordlist.py     # candidate password list generator
│   └── data/
│       └── common_words.txt
├── cli.py
├── requirements.txt
└── .gitignore
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All passwords scored ≥ 45 |
| 1 | No input provided |
| 2 | One or more passwords scored < 45 |

Non-zero exit on weak passwords makes this usable in pre-commit hooks or CI pipelines.

---

## dev comment

i didn't add the "emojis" in the first try, but it did feel like something is missing so i asked A.i and it told me to add "emojis" and he edited somefiles so now it feel like completed so yeha that's y this feels like a.i lol :> 

## Stack

Python · requests · hashlib · argparse