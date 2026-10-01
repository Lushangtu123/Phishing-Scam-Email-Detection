"""Throwaway RSA keys for ARC tests, generated at import: no key material is stored."""
import base64
import random


def _probable_prime(bits: int, rng: random.Random) -> int:
    witnesses = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    while True:
        # The top two bits set make the product of two such primes exactly 2 * bits long.
        candidate = rng.getrandbits(bits) | (3 << bits - 2) | 1
        d, s = candidate - 1, 0
        while d % 2 == 0:
            d, s = d // 2, s + 1
        for witness in witnesses:
            x = pow(witness, d, candidate)
            if x in (1, candidate - 1):
                continue
            for _ in range(s - 1):
                x = pow(x, 2, candidate)
                if x == candidate - 1:
                    break
            else:
                break
        else:
            return candidate


def _der(tag: int, content: bytes) -> bytes:
    size = len(content)
    if size < 0x80:
        return bytes([tag, size]) + content
    length = size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([tag, 0x80 | len(length)]) + length + content


def _sequence(*values: int) -> bytes:
    return _der(0x30, b''.join(_der(0x02, value.to_bytes(value.bit_length() // 8 + 1, 'big')) for value in values))


def make_key(bits: int = 1024) -> tuple[bytes, bytes]:
    """(PKCS#1 PEM private key, DNS TXT record value) for a fresh RSA key."""
    rng = random.SystemRandom()
    exponent = 65537
    while True:
        p, q = _probable_prime(bits // 2, rng), _probable_prime(bits // 2, rng)
        phi = (p - 1) * (q - 1)
        if p != q and phi % exponent:
            break
    n, d = p * q, pow(exponent, -1, phi)
    assert n.bit_length() == bits
    der = _sequence(0, n, exponent, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p))
    pem = b'-----BEGIN RSA PRIVATE KEY-----\n' + base64.encodebytes(der) + b'-----END RSA PRIVATE KEY-----\n'
    return pem, b'v=DKIM1; k=rsa; p=' + base64.b64encode(_sequence(n, exponent))
