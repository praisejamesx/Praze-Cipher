# Praze Postmortem

*What happens when grown-up me gets bored and decides to tear apart what 13yo me came up with.*

So I was digging through old projects and found this — the "Praze Cipher." Younger me was *very* proud. Thought I'd invented unbreakable encryption. Left comments like *"feel free to try hacking the cipher"* with the confidence of someone who had no idea what they were talking about.

Fueled by boredom and mild embarrassment, I decided to see how fast I could tear it apart.

Turns out: embarrassingly fast.

---

## The Cipher

Given a secret pair `(x, y)` and a key `(a, b)`:

1. `A = [x·a, x·b]`, `B = [y·a, y·b]`  
2. Cross products: `[x·y·a², x·y·a·b, x·y·a·b, x·y·b²]`  
3. Remove duplicate middle terms → **ciphertext = `(x·y·a², x·y·b²)`**

Every bigram encrypts to its product `x·y` scaled by `a²` and `b²`. That's it.

---

## 8 Fatal Flaws

| # | Flaw | Impact |
|---|------|--------|
| 1 | **Ratio Leakage**: `c₁/c₂ = a²/b²` for every pair | Key ratio visible immediately |
| 2 | **Product-only**: Only `x·y` is preserved | `(x,y)` and `(y,x)` produce identical output — "AB" = "BA" |
| 3 | **Deterministic**: Same bigram → same ciphertext | Classic codebook; frequency analysis applies |
| 4 | **GCD Leakage**: `gcd(all c₁)` divisible by `a²` | Key recovered in milliseconds |
| 5 | **Known-plaintext**: One known bigram = full key recovery | Two divisions |
| 6 | **Tiny key space**: `a, b` are small integers | Trivially brute-forceable |
| 7 | **No diffusion**: One character change affects only one pair | No avalanche effect |
| 8 | **Malleable**: Ciphertext can be modified undetected | No integrity/authenticity |

---

## Attacks

### Attack 1 — GCD Key Recovery (no plaintext needed)

```python
GCD of all c1 values = 144   ::  a = 12
GCD of all c2 values = 54756 ::  b = 234
```

Full key recovered. Zero plaintext known.

### Attack 2 — Known Plaintext (two divisions)

Know the message starts with `"He"`?

```
a² = c₁ / (ord('H') × ord('e')) = 144  ::  a = 12
b² = c₂ / (ord('H') × ord('e')) = 54756 ::  b = 234
```

### Attack 3 — Beam Search Decryption

With the key, each pair gives `P = x·y`. Factor P into valid ASCII and use bigram frequencies to resolve ordering:

| Sample | Accuracy |
|--------|----------|
| Ciphertext-only | ~68% |
| With known plaintext | 100% |

---

## What I Learned

1. **Don't roll your own crypto.** The gap between "this looks clever" and "this is totally broken" is about 15 minutes of an adult with a math background looking at it.
2. **Publishing your "unbreakable" cipher on GitHub is a bold move.** It will not age well.
3. **Kid me was onto something, sort of.** Double Multiplication as a one-way function isn't dumb, it's just incomplete. Real crypto needs structure this completely lacks.

---

*Filed under: things I made as a kid that should've stayed in a private repo*

Now I wonder what nonsense I'm building today that future-me will tear apart next
