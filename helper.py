# helper functions
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
import base64
import sys
import re
from math import log as _log

def integer_nthroot(y, n):
    """
    Return a tuple containing x = floor(y**(1/n))
    and a boolean indicating whether the result is exact (that is,
    whether x**n == y).

    >>> from sympy import integer_nthroot
    >>> integer_nthroot(16,2)
    (4, True)
    >>> integer_nthroot(26,2)
    (5, False)

    """
    y, n = int(y), int(n)
    if y < 0:
        raise ValueError("y must be nonnegative")
    if n < 1:
        raise ValueError("n must be positive")
    if y in (0, 1):
        return y, True
    if n == 1:
        return y, True
    if n == 2:
        x, rem = _sqrtrem_python(y)
        return int(x), not rem
    if n > y:
        return 1, False
    # Get initial estimate for Newton's method. Care must be taken to
    # avoid overflow
    try:
        guess = int(y**(1./n) + 0.5)
    except OverflowError:
        exp = _log(y, 2)/n
        if exp > 53:
            shift = int(exp - 53)
            guess = int(2.0**(exp - shift) + 1) << shift
        else:
            guess = int(2.0**exp)
    if guess > 2**50:
        # Newton iteration
        xprev, x = -1, guess
        while 1:
            t = x**(n - 1)
            xprev, x = x, ((n - 1)*x + y//t)//n
            if abs(x - xprev) < 2:
                break
    else:
        x = guess
    # Compensate
    t = x**n
    while t < y:
        x += 1
        t = x**n
    while t > y:
        x -= 1
        t = x**n
    return x, t == y

def integer_to_bytes(n, length=None):
    '''Converts an arbitrarily long integer to bytes, big-endian (Python 3)'''
    # Calculate length if not provided, ensuring it's long enough for the modulus
    L = length or (n.bit_length() + 7) // 8
    # Use explicit length of 256 bytes (2048 bits) for RSA modulus N
    return n.to_bytes(256, byteorder='big') 

def integer_to_base64(z):
    '''Converts an arbitrarily long integer to a big-endian base64 encoding (Python 3)'''
    s_bytes = integer_to_bytes(z)
    encoded_bytes = base64.b64encode(s_bytes)
    return encoded_bytes.decode('utf-8')

def bytes_to_integer(b):
    '''Converts big-endian bytes to an arbitrarily long integer (Python 3)'''
    return int.from_bytes(b, byteorder='big')


def verify_rsa(public_key, original_message, signature_integer):
    '''
    Verifies an RSA signature by checking if the decrypted message
    contains the required PKCS#1 v1.5 padding and hash ASN.1 prefix.
    This simulates a vulnerable verification check.
    '''
    # Decrypt the signature using the public key: M' = S^e mod N
    decrypted_int = pow(signature_integer, public_key.e, public_key.n)
    
    decrypted_bytes = integer_to_bytes(decrypted_int, length=256)
    decrypted_hex = decrypted_bytes.hex()

    # Create the expected hash
    message_hash = SHA.new(original_message.encode('utf-8')).hexdigest()
    asn1_prefix = '3021300906052b0e03021a05000414'
    
    pattern = r'^0001f.*' + re.escape(asn1_prefix) + re.escape(message_hash) + r'.*$'
    vulnerable_check = re.match(pattern, decrypted_hex)

    return bool(vulnerable_check)
