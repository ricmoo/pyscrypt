# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


import hashlib
import hmac

from .pbkdf2 import pbkdf2


def integerify(B, Bi, r):
    '''"A bijective function from ({0, 1} ** k) to {0, ..., (2 ** k) - 1".'''

    Bi += (2 * r - 1) * 64
    n  = B[Bi] | (B[Bi + 1] << 8) | (B[Bi + 2] << 16) | (B[Bi + 3] << 24)
    return n

def make_int32(v):
    '''Converts (truncates, two's compliments) a number to an int32.'''

    if v > 0x7fffffff: return -1 * ((~v & 0xffffffff) + 1)
    return v


ROUNDS = [
    (4, 0, 12, 7),   (8, 4, 0, 9),    (12, 8, 4, 13),   (0, 12, 8, 18),
    (9, 5, 1, 7),    (13, 9, 5, 9),   (1, 13, 9, 13),   (5, 1, 13, 18),
    (14, 10, 6, 7),  (2, 14, 10, 9),  (6, 2, 14, 13),   (10, 6, 2, 18),
    (3, 15, 11, 7),  (7, 3, 15, 9),   (11, 7, 3, 13),   (15, 11, 7, 18),
    (1, 0, 3, 7),    (2, 1, 0, 9),    (3, 2, 1, 13),    (0, 3, 2, 18),
    (6, 5, 4, 7),    (7, 6, 5, 9),    (4, 7, 6, 13),    (5, 4, 7, 18),
    (11, 10, 9, 7),  (8, 11, 10, 9),  (9, 8, 11, 13),   (10, 9, 8, 18),
    (12, 15, 14, 7), (13, 12, 15, 9), (14, 13, 12, 13), (15, 14, 13, 18),
]


def salsa20_8(B):
    '''Salsa 20/8 stream cypher; Used by BlockMix. See http://en.wikipedia.org/wiki/Salsa20'''

    # Convert the character array into an int32 array
    B32 = [ make_int32((B[i * 4] | (B[i * 4 + 1] << 8) | (B[i * 4 + 2] << 16) | (B[i * 4 + 3] << 24))) for i in xrange(0, 16) ]
    x = [ i for i in B32 ]

    # Salsa... Time to dance.
    for i in (8, 6, 4, 2):
        for (destination, a1, a2, b) in ROUNDS:
            a = (x[a1] + x[a2]) & 0xffffffff
            x[destination] ^= ((a << b) | (a >> (32 - b)))

    # Coerce into nice happy 32-bit integers
    B32 = [ make_int32(x[i] + B32[i]) for i in xrange(0, 16) ]

    # Convert back to bytes
    for i in xrange(0, 16):
        B[i * 4 + 0] = (B32[i] >> 0) & 0xff
        B[i * 4 + 1] = (B32[i] >> 8) & 0xff
        B[i * 4 + 2] = (B32[i] >> 16) & 0xff
        B[i * 4 + 3] = (B32[i] >> 24) & 0xff


def blockmix_salsa8(BY, Bi, Yi, r):
    '''Blockmix; Used by SMix.'''

    start = Bi + (2 * r - 1) * 64
    X = [ BY[i] for i in xrange(start, start + 64) ]              # BlockMix - 1

    for i in xrange(0, 2 * r):                                    # BlockMix - 2

        for xi in xrange(0, 64):                                   # BlockMix - 3(inner)
            X[xi] ^= BY[i * 64 + xi]

        salsa20_8(X)                                              # BlockMix - 3(outer)
        aod = Yi + (i * 64)                                       # BlockMix - 4
        BY[aod:aod + 64] = X[:64]

    for i in xrange(0, r):                                        # BlockMix - 6 (and below)
        aos = Yi + (i * 2) * 64
        aod = Bi + (i * 64)
        BY[aod:aod + 64] = BY[aos:aos + 64]

    for i in xrange(0, r):
        aos = Yi + (i * 2 + 1) * 64
        aod = Bi + (i + r) * 64
        BY[aod:aod + 64] = BY[aos:aos + 64]


def smix(B, Bi, r, N, V, X):
    '''SMix; a specific case of ROMix. See scrypt.pdf in the links above.'''

    X[:128 * r] = B[Bi:Bi + 128 * r]                   # ROMix - 1

    for i in xrange(0, N):                             # ROMix - 2
        aod = i * 128 * r                              # ROMix - 3
        V[aod:aod + 128 * r] = X[:128 * r]
        blockmix_salsa8(X, 0, 128 * r, r)              # ROMix - 4

    for i in xrange(0, N):                             # ROMix - 6
        j = integerify(X, 0, r) & (N - 1)              # ROMix - 7
        for xi in xrange(0, 128 * r):                  # ROMix - 8(inner)
            X[xi] ^= V[j * (128 * r) + xi]

        blockmix_salsa8(X, 0, 128 * r, r)              # ROMix - 9(outer)

    B[Bi:Bi + 128 * r] = X[:128 * r]                   # ROMix - 10



def hash(password, salt, N, r, p, dkLen):
    """Returns the result of the scrypt password-based key derivation function.

       Constraints:
         r * p < (2 ** 30)
         dkLen <= (((2 ** 32) - 1) * 32
         N must be a power of 2 greater than 1 (eg. 2, 4, 8, 16, 32...)
         N, r, p must be positive
     """

    # Scrypt implementation. Significant thanks to https://github.com/wg/scrypt
    if N < 2 or (N & (N - 1)): raise ValueError('Scrypt N must be a power of 2 greater than 1')

    # A psuedorandom function
    prf = lambda k, m: hmac.new(key = k, msg = m, digestmod = hashlib.sha256).digest()

    B  = [ ord(c) for c in pbkdf2(password, salt, 1, p * 128 * r, prf) ]
    XY = [ 0 ] * (256 * r)
    V  = [ 0 ] * (128 * r * N)

    for i in xrange(0, p):
        smix(B, i * 128 * r, r, N, V, XY)

    return pbkdf2(password, ''.join(chr(c) for c in B), 1, dkLen, prf)
