import os

def load_bundled_wordlist():
    p = os.path.join(os.path.dirname(__file__), 'data', 'common_words.txt')
    if not os.path.exists(p):
        return set()
    return {l.strip().lower() for l in open(p) if l.strip()}