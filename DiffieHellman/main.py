from dh.prime import generate_safe_prime, find_generator
from dh.primitive_root import find_primitive_root
from dh.diffie_hellman import DiffieHellman
from dh.crypto_utils import derive_key, encrypt, decrypt


p, q = generate_safe_prime(256)
g = find_generator(p, q)

print("p =", p)
print("g =", g)

alice = DiffieHellman(p, g)
bob = DiffieHellman(p, g)

print("\nAlice public:", alice.public)
print("Bob public:  ", bob.public)

K1 = alice.compute_shared_key(bob.public)
K2 = bob.compute_shared_key(alice.public)

print("\nShared keys equal:", K1 == K2)

key = derive_key(K1)

with open("message.txt", "rb") as f:
    message = f.read()
iv, ciphertext = encrypt(key, message)

print("\nCiphertext:", ciphertext)

plaintext = decrypt(key, iv, ciphertext)
print("\nDecrypted message:", plaintext.decode(),"\n")
