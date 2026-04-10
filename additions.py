"""
practical part
"""
import hashlib
import random
import math

def get_hash(message):
    """Generate a SHA-256 hexadecimal hash of the input string for integrity verification."""
    return hashlib.sha256(message.encode()).hexdigest()

def is_prime(n):
    """Check if a number is prime using the trial division method."""
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_keys():
    """Generate a pair of RSA public and private keys using random prime numbers."""
    primes = [i for i in range(100, 300) if is_prime(i)]
    p, q = random.sample(primes, 2)
    n = p * q
    phi_func = (p - 1) * (q - 1)
    e = 65537
    if e >= phi_func or math.gcd(e, phi_func) != 1:
        e = 3
        while math.gcd(e, phi_func) != 1:
            e += 2
    d = pow(e, -1, phi_func)
    return (e, n), (d, n)

def encrypt(message, key):
    """Encrypt a string into a list of integers using the RSA public key."""
    e, n = key
    return [pow(ord(char), e, n) for char in message]

def decrypt(encrypted_msg, key):
    """Decrypt a list of RSA-encrypted integers back into a string using the private key."""
    d, n = key
    return "".join([chr(pow(char, d, n)) for char in encrypted_msg])
