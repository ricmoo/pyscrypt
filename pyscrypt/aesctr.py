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

# This file relies a great deal on the slowaes library (https://code.google.com/p/slowaes/)
# which is released under the Apache License 2.0.

import slowaes

class Counter(object):
    def __init__(self, nbits, initial_value = 1):
        if nbits % 8 != 0: raise ValueError('invalid counter length')
        self._counter = [ 0 ] * (nbits // 8)

        # Initialize the vector with the initial value
        index = len(self._counter) - 1
        while initial_value:
            self._counter[index] = initial_value % 256
            initial_value //= 256
            index -= 1
            if index == -1: raise ValueError('initial_value too large')

        # Generator that returns big-endian ++ operations on our counter array
        def next_value(self):
          while True:
            yield self._counter

            # Add one to the right-most byte of the counter and carry if overflows a byte
            index = len(self._counter) - 1
            while True:
                self._counter[index] += 1

                # Carry...
                if self._counter[index] == 256:
                    self._counter[index] = 0
                    index -= 1

                    # Overflow... Wrap around
                    if index == -1:
                        self._counter = [ 0 ] * 16
                        break
                else:
                    break

        self._next_value = next_value(self)

    def __call__(self):
        return self._next_value.next()


class AESCounterModeOfOperation(object):

    def __init__(self, key, counter):
        self._key = [ ord(c) for c in key ]

        self._counter = counter
        self._remaining_counter = [ ]
        self._aes = slowaes.AES()

    def encrypt(self, plaintext):
        encrypted = [ ]
        for c in plaintext:
            if len(self._remaining_counter) == 0:
                self._remaining_counter = self._aes.encrypt(self._counter(), self._key, len(self._key))
            encrypted.append(self._remaining_counter.pop(0) ^ ord(c))

        return "".join(chr(c) for c in encrypted)

    def decrypt(self, crypttext):
        # AES-CTR is symetric
        return self.encrypt(crypttext)


if __name__ == '__main__':
    import os

    # compare against a known working implementation
    try:
        from Crypto.Cipher import AES as KAES
        from Crypto.Util import Counter as KCounter

        for key_size in (128, 192, 256):
            for text_length in [3, 16, 127, 128, 129, 1500]:

                # Try 10 different values
                for i in xrange(0, 10):
                    key = os.urandom(key_size // 8)
                    plaintext = os.urandom(text_length)

                    kaes = KAES.new(key, KAES.MODE_CTR, counter = KCounter.new(128, initial_value = 0))
                    kenc = kaes.encrypt(plaintext)

                    aes = AESCounterModeOfOperation(key, counter = Counter(nbits = 128, initial_value = 0))
                    enc = aes.encrypt(plaintext)

                    result = {True: "pass", False: "fail"}[kenc == enc]
                    print "Test Encrypt: key_size=%d text_length=%d trial=%d result=%s" % (key_size, text_length, i, result)

                    aes = AESCounterModeOfOperation(key, counter = Counter(nbits = 128, initial_value = 0))
                    result = {True: "pass", False: "fail"}[plaintext == aes.decrypt(kenc)]
                    print "Test Decrypt: key_size=%d text_length=%d trial=%d result=%s" % (key_size, text_length, i, result)

    except Exception, e:
        print e
