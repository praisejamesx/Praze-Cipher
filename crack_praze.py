"""
Praze Cipher — Complete Cryptanalysis Suite

Three attacks that reduce the "unbreakable" cipher to a pile of rubble:

  Attack 1 — GCD Key Recovery (ciphertext only, no plaintext)
  Attack 2 — Known Plaintext Key Recovery (one bigram is enough)
  Attack 3 — Beam Search Decryption (bigram statistics)

Run:  python crack_praze.py
"""

import math
import random
from collections import defaultdict

ASCII_MIN = 32
ASCII_MAX = 126
VALID_CHARS = list(range(ASCII_MIN, ASCII_MAX + 1))


# ─── English bigram frequencies (top ~300, normalized) ───────────────────
# Source: standard English bigram frequency table
BIGRAM_FREQ = {
    "TH": 3.56, "HE": 3.07, "IN": 2.43, "ER": 2.05, "AN": 1.99,
    "RE": 1.85, "ND": 1.34, "AT": 1.33, "ON": 1.32, "NT": 1.17,
    "HA": 1.13, "ES": 1.13, "ST": 1.05, "EN": 1.04, "ED": 1.00,
    "TO": 0.97, "IT": 0.96, "OU": 0.94, "EA": 0.93, "HI": 0.92,
    "IS": 0.91, "OR": 0.90, "TI": 0.88, "AS": 0.87, "TE": 0.83,
    "ET": 0.80, "NG": 0.77, "AL": 0.76, "OF": 0.75, "BE": 0.74,
    "SE": 0.72, "LE": 0.72, "SA": 0.66, "SI": 0.64, "AR": 0.63,
    "ME": 0.62, "RA": 0.62, "VE": 0.60, "NE": 0.59, "CO": 0.59,
    "LL": 0.58, "DE": 0.57, "RO": 0.56, "RT": 0.56, "TA": 0.55,
    "CE": 0.54, "IC": 0.54, "EL": 0.53, "NS": 0.53, "DI": 0.53,
    "WO": 0.02, "ZZ": 0.01, "QQ": 0.01,
}

# Build quick lookup
_BIGRAM_SCORE = {b: s for b, s in BIGRAM_FREQ.items()}


def _bigram_score(bg):
    return _BIGRAM_SCORE.get(bg.upper(), 0.01)


def gcd_of_list(nums):
    result = 0
    for n in nums:
        result = math.gcd(result, n)
    return result


# ─── Attack 1: Key Recovery from Ciphertext Alone ────────────────────────

def recover_key_from_gcd(ciphertext_pairs):
    """
    Attack 1: Full key recovery using GCD leakage (Flaw #4).

    Since c1 = x*y*a² and c2 = x*y*b² for each pair, the GCD of all c1
    values is divisible by a², and GCD of all c2 values by b².
    """
    c1_vals = [p[0] for p in ciphertext_pairs]
    c2_vals = [p[1] for p in ciphertext_pairs]

    gcd_c1 = gcd_of_list(c1_vals)
    gcd_c2 = gcd_of_list(c2_vals)

    print(f"  GCD of all c1 values = {gcd_c1}")
    print(f"  GCD of all c2 values = {gcd_c2}")

    found = []
    for a_candidate in range(1, int(math.isqrt(gcd_c1)) + 1):
        a2 = a_candidate * a_candidate
        if gcd_c1 % a2 != 0:
            continue
        for b_candidate in range(1, int(math.isqrt(gcd_c2)) + 1):
            b2 = b_candidate * b_candidate
            if gcd_c2 % b2 != 0:
                continue

            valid = True
            for c1, c2 in ciphertext_pairs:
                if c1 % a2 != 0 or c2 % b2 != 0:
                    valid = False
                    break
                p1 = c1 // a2
                p2 = c2 // b2
                if p1 != p2:
                    valid = False
                    break
                has_factor = False
                for x in VALID_CHARS:
                    if p1 % x == 0 and ASCII_MIN <= p1 // x <= ASCII_MAX:
                        has_factor = True
                        break
                if not has_factor:
                    valid = False
                    break

            if valid:
                found.append((a_candidate, b_candidate))

    return found


# ─── Attack 2: Known Plaintext Key Recovery ─────────────────────────────

def recover_key_from_known_bigram(x, y, c1, c2):
    """
    Attack 2: Recover key from a single known bigram (Flaw #5).

    If you know that ciphertext (c1, c2) corresponds to bigram (x, y):
        a² = c1 / (x*y)
        b² = c2 / (x*y)
    """
    product = x * y
    a2 = c1 // product
    b2 = c2 // product
    a = int(math.isqrt(a2))
    b = int(math.isqrt(b2))

    if a * a == a2 and b * b == b2:
        return (a, b)
    return None


# ─── Attack 3: Beam Search Decryption ────────────────────────────────────

def factor_product(product):
    factors = []
    for x in range(ASCII_MIN, ASCII_MAX + 1):
        if product % x == 0:
            y = product // x
            if ASCII_MIN <= y <= ASCII_MAX:
                factors.append((x, y))
    return factors


def score_bigram_pair(pair, prev_char=None):
    """Score a (x, y) byte pair as a English bigram."""
    if prev_char is not None:
        bg = chr(prev_char) + chr(pair[0])
        score = _bigram_score(bg.upper())
    else:
        score = 0
    bg2 = chr(pair[0]) + chr(pair[1])
    score += _bigram_score(bg2.upper())
    return score


def decrypt_beam_search(ciphertext_pairs, a, b, beam_width=5):
    """
    Attack 3: Decrypt using beam search with bigram statistics.

    Each ciphertext pair yields x*y = c1/a² = c2/b², but (x,y) and (y,x)
    are both valid. We use English bigram frequencies to pick the best
    path through the ambiguity.
    """
    a2 = a * a
    b2 = b * b

    products = [c1 // a2 for c1, _ in ciphertext_pairs]
    candidates = []
    for prod in products:
        candidates.append(factor_product(prod))

    beam = [([], 0.0, None)]

    for pos, cand_list in enumerate(candidates):
        if not cand_list:
            beam = [(seq, score - 1, prev) for seq, score, prev in beam]
            continue

        new_beam = []
        for seq, score, prev_char in beam:
            for x, y in cand_list:
                new_seq = seq + [(x, y)]
                pair_score = score_bigram_pair((x, y), prev_char)
                total_score = score + pair_score
                new_beam.append((new_seq, total_score, y))

        new_beam.sort(key=lambda t: -t[1])
        beam = new_beam[:beam_width]

    best_seq = max(beam, key=lambda t: t[1])[0]
    result = ''.join(chr(c) for pair in best_seq for c in pair)
    return result


# ─── Helpers for demonstration ──────────────────────────────────────────

def encrypt(text, a, b):
    chars = [ord(c) for c in text]
    if len(chars) % 2:
        chars.append(ord(' '))
    pairs = [(chars[i], chars[i+1]) for i in range(0, len(chars), 2)]
    return [(x * y * a * a, x * y * b * b) for x, y in pairs]


# ─── Self-contained demo ─────────────────────────────────────────────────

def demo():
    print("=" * 60)
    print("  PRAZE CIPHER -- COMPLETE CRYPTANALYSIS SUITE")
    print("  Tearing apart the 'unbreakable' cipher, one flaw at a time")
    print("=" * 60)

    # ── Setup ────────────────────────────────────────────────────────
    key_a, key_b = 12, 234
    plaintext = "Hello World! This is a secret message. Cryptography is fun."
    print(f"\n[Setup]")
    print(f"  Key:       a = {key_a}, b = {key_b}")
    print(f"  Plaintext: {plaintext}")

    ct = encrypt(plaintext, key_a, key_b)
    print(f"  Ciphertext pairs: {len(ct)} bigrams encrypted")
    print(f"  First 3 pairs:    {ct[:3]}")

    # ── Attack 1: GCD Key Recovery ───────────────────────────────────
    print(f"\n{'-' * 60}")
    print("  ATTACK 1 -- GCD Key Recovery (ciphertext-only)")
    print(f"{'-' * 60}")
    candidates = recover_key_from_gcd(ct)
    if candidates:
        a_rec, b_rec = candidates[0]
        print(f"  [OK] Recovered key: a = {a_rec}, b = {b_rec}")
        print(f"  [OK] Match original: {(a_rec, b_rec) == (key_a, key_b)}")
        if len(candidates) > 1:
            print(f"  Ambiguity: {len(candidates)} candidates (trying first)")
    else:
        print("  [FAIL] Key recovery failed (unexpected)")
        return

    # ── Attack 2: Known Plaintext ────────────────────────────────────
    print(f"\n{'-' * 60}")
    print("  ATTACK 2 -- Known Plaintext Key Recovery")
    print(f"{'-' * 60}")
    known_bigram = (ord('H'), ord('e'))
    c1_known, c2_known = ct[0]
    recovered = recover_key_from_known_bigram(known_bigram[0], known_bigram[1],
                                               c1_known, c2_known)
    if recovered:
        print(f"  Known bigram: 'He' -> ({c1_known}, {c2_known})")
        print(f"  [OK] Recovered: a = {recovered[0]}, b = {recovered[1]}")
        print(f"  [OK] Match: {(recovered[0], recovered[1]) == (key_a, key_b)}")
    else:
        print("  [FAIL] Key recovery from known plaintext failed")

    # ── Attack 3: Beam Search Decryption ─────────────────────────────
    print(f"\n{'-' * 60}")
    print("  ATTACK 3 -- Beam Search Decryption")
    print(f"{'-' * 60}")
    decrypted = decrypt_beam_search(ct, key_a, key_b, beam_width=5)
    matches = sum(1 for a, b in zip(plaintext, decrypted) if a == b)
    accuracy = 100.0 * matches / len(plaintext)
    print(f"  Original:  {plaintext}")
    print(f"  Decrypted: {decrypted}")
    print(f"  Accuracy:  {accuracy:.1f}% ({matches}/{len(plaintext)} chars)")

    # ── Summary ──────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print("  SUMMARY -- All 8 Flaws Exposed")
    print(f"{'=' * 60}")
    flaws = [
        ("1. Ratio Leakage", "c1/c2 = a^2/b^2 leaked from every pair"),
        ("2. Product-only", "Order lost -- 'AB' == 'BA' always"),
        ("3. Deterministic", "Same bigram -> same ciphertext (codebook)"),
        ("4. GCD Leakage", f"GCD gave us a={a_rec}, b={b_rec} instantly"),
        ("5. Known-plaintext", "One bigram -> full key in 2 divisions"),
        ("6. Tiny key space", "a,b are tiny -- trivially brute-forced"),
        ("7. No diffusion", "One char change affects only one bigram"),
        ("8. Malleable", "No authentication -- ciphertext can be tampered"),
    ]
    for name, desc in flaws:
        print(f"  [BAD] {name:<25s} -- {desc}")

    print(f"\n  Bottom line: The Praze Cipher is a mathematical curiosity,")
    print(f"  not encryption. Don't roll your own crypto.")


if __name__ == "__main__":
    demo()
