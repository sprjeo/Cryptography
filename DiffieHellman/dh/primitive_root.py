def prime_factors(n):
    factors = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    return factors


def find_primitive_root(p):
    phi = p - 1
    factors = prime_factors(phi)

    for g in range(2, p):
        for q in factors:
            if pow(g, phi // q, p) == 1:
                break
        else:
            return g
