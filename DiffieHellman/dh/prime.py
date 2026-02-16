import random

def is_prime(n, k=40):
    if n < 2:
        return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n % p == 0:
            return n == p

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_safe_prime(bits=256):
    while True:
        q = random.getrandbits(bits - 1)
        q |= (1 << (bits - 2)) | 1
        if is_prime(q):
            p = 2*q + 1
            if is_prime(p):
                return p, q


def find_generator(p, q):
    while True:
        g = random.randint(2, p - 2)
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g
