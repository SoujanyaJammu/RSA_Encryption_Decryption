"""
RSA implementation:
- Extended Euclidean algorithm for modular inverse
- Key generation (using sympy.randprime)
- JSON save/load of keys (public + private)
- Base64 encoding for ciphertext representation
"""

import json
import base64
from math import gcd
from sympy import randprime


# -------------------------
# 1. Extended Euclid (modular inverse)
# -------------------------
def extended_gcd(a: int, b: int):
    """Return (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def modinv(a: int, m: int) -> int:
    """Return modular inverse of a modulo m, i.e., a^(-1) mod m."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    return x % m


# -------------------------
# 2. Key generation + JSON persistence
# -------------------------
def generate_keys(bits: int = 2048, e: int = 65537):
    """
    Generate RSA public/private key pair.
    Returns:
        public = (e, n)
        private = (d, n)
    """
    # generate two distinct primes ~ bits/2 each
    p = randprime(2 ** (bits // 2 - 1), 2 ** (bits // 2))
    q = randprime(2 ** (bits // 2 - 1), 2 ** (bits // 2))
    while q == p:
        q = randprime(2 ** (bits // 2 - 1), 2 ** (bits // 2))

    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd(e, phi) != 1:
        raise ValueError("e not coprime with phi; regenerate primes or choose different e")

    d = modinv(e, phi)

    public = (e, n)
    private = (d, n)
    return public, private


def save_keys_json(pub: tuple, priv: tuple, path: str = "keys.json"):
    """
    Save public/private key to a JSON file.
    Only stores (e, n, d).
    """
    e, n = pub
    d, _ = priv
    data = {"e": e, "n": n, "d": d}
    with open(path, "w") as f:
        json.dump(data, f)
    return path


def load_keys_json(path: str = "keys.json"):
    """
    Load public/private key from a JSON file.
    Returns:
        pub = (e, n)
        priv = (d, n)
    """
    with open(path, "r") as f:
        k = json.load(f)

    e = int(k["e"])
    n = int(k["n"])
    d = int(k["d"])

    pub = (e, n)
    priv = (d, n)

    return pub, priv


# -------------------------
# 3. Helpers: text <-> int, base64
# -------------------------
def text_to_int(s: str) -> int:
    """UTF-8 string -> integer."""
    b = s.encode("utf-8")
    return int.from_bytes(b, byteorder="big")


def int_to_text(i: int) -> str:
    """Integer -> UTF-8 string."""
    if i == 0:
        return ""
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, byteorder="big").decode("utf-8")


def int_to_b64(i: int) -> str:
    """Integer -> base64 string (for readable ciphertext)."""
    if i == 0:
        b = b"\x00"
    else:
        length = (i.bit_length() + 7) // 8
        b = i.to_bytes(length, "big")
    return base64.b64encode(b).decode()


def b64_to_int(s: str) -> int:
    """Base64 string -> integer."""
    b = base64.b64decode(s.encode())
    return int.from_bytes(b, "big")


# -------------------------
# 4. Encrypt / Decrypt
# -------------------------
def encrypt_int(m: int, pub: tuple) -> int:
    """Encrypt integer m using public key (e, n)."""
    e, n = pub
    if not (0 <= m < n):
        raise ValueError(f"Plain integer must satisfy 0 <= m < n. Got m={m}, n={n}")
    return pow(m, e, n)


def decrypt_int(c: int, priv: tuple) -> int:
    """Decrypt integer c using private key (d, n)."""
    d, n = priv
    return pow(c, d, n)


def encrypt_text(plaintext: str, pub: tuple) -> str:
    """
    Encrypt a UTF-8 string using RSA and return base64 ciphertext.
    """
    m_int = text_to_int(plaintext)
    _, n = pub
    if m_int >= n:
        raise ValueError(
            "Message integer representation too large for modulus n. "
            "Use larger key or shorter message."
        )
    c = encrypt_int(m_int, pub)
    return int_to_b64(c)


def decrypt_text_b64(cipher_b64: str, priv: tuple) -> str:
    """
    Decrypt a base64-encoded ciphertext string using RSA.
    Returns the recovered UTF-8 plaintext (or integer as string if decoding fails).
    """
    c_int = b64_to_int(cipher_b64)
    m_int = decrypt_int(c_int, priv)
    try:
        return int_to_text(m_int)
    except Exception:
        return str(m_int)
