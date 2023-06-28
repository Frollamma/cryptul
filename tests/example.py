from hashlib import sha1
from Crypto.Util.number import bytes_to_long, inverse
import time
from cryptul import DSACracker
import random
from sympy import Mod


def sign(m, g, p, q, x, k):
    H = bytes_to_long(sha1(m).digest())
    r = pow(g, k, p) % q
    s = (inverse(k, q) * (H + x * r)) % q
    assert s != 0
    return hex(r)[2:].rjust(40, "0") + hex(s)[2:].rjust(40, "0")


def verify(m, sig, g, p, q, y):
    r, s = int(sig[:40], 16), int(sig[40:], 16)
    a = pow(g, (bytes_to_long(sha1(m).digest()) * inverse(s, q)) % q, p)
    b = pow(y, (r * inverse(s, q)) % q, p)
    return (a * b % p) % q == r


def extract_signature_pair(signature_string):
    r, s = int(signature_string[:40], 16), int(signature_string[40:], 16)
    return r, s


def H(message: bytes) -> int:
    return bytes_to_long(sha1(message).digest())


q = 7  # Prime number
p = 29  # Prime number such that q | p-1
h = random.randint(2, p - 2)
x = random.randint(1, q - 1)
k = random.randint(1, q - 1)
l = 2

dsa = DSACracker(p, q, H, h=h, x=x)
print(f"{p, q, h, x, dsa.g, dsa.y = }")
print(f"{dsa.p, dsa.q, dsa.h, dsa.x, dsa.g, dsa.y = }")

message = b"enzo"
signature1 = sign(message, dsa.g, p, q, x, k)
signature2 = sign(message, dsa.g, p, q, x, k + l)

r1, s1 = extract_signature_pair(signature1)
r2, s2 = extract_signature_pair(signature2)

# Test of get_x_given_message_and_seed
x_guess = dsa.get_x_given_message_and_seed(message, r1, s1, k)
print(f"{x, x_guess = }")
assert x_guess == x, "get_x_given_message_and_seed test failed"
print(f"{dsa.p, dsa.q, dsa.h, dsa.x, dsa.g, dsa.y = }")

# Test of get_seed_given_linear_relation
k_guess = dsa.get_seed_given_linear_relation(message, s1, s2, l)
print(f"{k, k_guess = }")

assert Mod(pow(dsa.g, k + l, dsa.p), dsa.q) == r2
assert (
    pow(dsa.g, k, dsa.p) * pow(dsa.g, l, dsa.p)
) % dsa.q == r2  # Here is the error! One haas that pow(dsa.g, k + l, dsa.p) = pow(dsa.g, k, dsa.p) * pow(dsa.g, l, dsa.p) % p != pow(dsa.g, k, dsa.p) * pow(dsa.g, l, dsa.p)
d = Mod(pow(dsa.g, l, dsa.p), dsa.q)
assert Mod(r1 * d, dsa.q) == r2
c = Mod(s2 - d * s1, dsa.q)
z = dsa.H(message)


assert k_guess == k, "get_seed_given_linear_relation test failed"
print(f"{dsa.p, dsa.q, dsa.h, dsa.x, dsa.g, dsa.y = }")

x_guess = dsa.get_x_given_message_and_seed(message, r1, s1, k_guess)
print(f"{x, x_guess = }")
assert x_guess == x

# Test if sign
r, s = dsa.sign(message, k_guess)
signature = hex(r)[2:].rjust(40, "0") + hex(s)[2:].rjust(40, "0")
assert signature == signature1
