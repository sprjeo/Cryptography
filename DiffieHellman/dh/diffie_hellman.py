import random

class DiffieHellman:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.secret = random.randint(2, p - 2)
        self.public = pow(g, self.secret, p)

    def compute_shared_key(self, other_public):
        return pow(other_public, self.secret, self.p)

