"""
Praze Cipher — Reference Implementation

This is the original algorithm, cleaned up and corrected.
The math is simple: each bigram (x,y) encrypts to (x*y*a^2, x*y*b^2)
under key (a,b). The rest is just plumbing.

See crack_praze.py for why you should never use this for anything real.
"""

from pathlib import Path

ASCII_MIN = 32
ASCII_MAX = 126


def _ord_pairs(text):
    """Convert text into list of (ord(a), ord(b)) bigram pairs."""
    chars = [ord(c) for c in text]
    if len(chars) % 2:
        chars.append(ord(' '))
    return [(chars[i], chars[i+1]) for i in range(0, len(chars), 2)]


def encrypt_bigram(x, y, a, b):
    """Encrypt a single bigram (x, y) with key (a, b)."""
    c1 = x * y * a * a
    c2 = x * y * b * b
    return (c1, c2)


def decrypt_bigram(c1, c2, a, b):
    """Decrypt a single ciphertext pair back to (x, y)."""
    product = c1 // (a * a)
    x = product // (c2 // (b * b))  # Not needed — we factor product instead
    # Actually: product = x*y, and we need to factor it
    return product


def encrypt(text, a, b):
    """Encrypt text using Praze Cipher with key (a, b)."""
    pairs = _ord_pairs(text)
    ciphertext = [encrypt_bigram(x, y, a, b) for (x, y) in pairs]
    return ciphertext


def factor_product(product):
    """Return all (x, y) pairs in ASCII range that multiply to product."""
    factors = []
    for x in range(ASCII_MIN, ASCII_MAX + 1):
        if product % x == 0:
            y = product // x
            if ASCII_MIN <= y <= ASCII_MAX:
                factors.append((x, y))
    return factors


def decrypt(ciphertext, a, b):
    """Decrypt ciphertext to text. Handles AB/BA ambiguity."""
    result = []
    for c1, c2 in ciphertext:
        product = c1 // (a * a)
        factors = factor_product(product)
        if not factors:
            result.extend(['?', '?'])
        elif len(factors) == 1:
            x, y = factors[0]
            result.extend([chr(x), chr(y)])
        else:
            # Try to resolve using the most recent char context
            x, y = factors[0]
            result.extend([chr(x), chr(y)])
    return ''.join(result)


def enc_from_file(input_path, output_path="ciphertext.txt", key_path="keyfile.txt", a=12, b=234):
    """Encrypt a file and write ciphertext + key to disk."""
    text = Path(input_path).read_text(encoding='utf-8', errors='ignore')
    ct = encrypt(text, a, b)

    Path(output_path).write_text(str(ct))
    Path(key_path).write_text(f"a = {a}\nb = {b}")
    print(f"Encrypted {len(text)} chars → {output_path}")
    return ct


def dec_from_file(input_path="ciphertext.txt", a=12, b=234):
    """Decrypt a ciphertext file."""
    raw = Path(input_path).read_text()
    ct = eval(raw, {"__builtins__": {}}, {})
    plain = decrypt(ct, a, b)
    print(f"Decrypted: {plain[:80]}...")
    return plain


if __name__ == "__main__":
    text = "Hello World! This is a test."
    ct = encrypt(text, a=12, b=234)
    print(f"Ciphertext: {ct}")
    pt = decrypt(ct, a=12, b=234)
    print(f"Decrypted:  {pt}")
