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

import sys
sys.path += '..'

import pyscrypt

print "Version:", ".".join(str(p) for p in pyscrypt.VERSION)

Tests = [
    dict(password = 'password', salt = 'salt', N = 2, r = 1, p = 1, dkLen = 32, result = '6d1bb878eee9ce4a7b77d7a44103574d4cbfe3c15ae3940f0ffe75cd5e1e0afa'),
    dict(password = 'password', salt = 'salt', N = 32, r = 4, p = 15, dkLen = 128, result = '19f255f7dbcc4128e3467c78c795cb934a82bb813793d2634f6e3adbaee1f54b118fca8b067ab4aad3f6557c716b3734bb93a5cb40500b5e42dc96ccee260fc64d8e660b80e7aecd81c83fefedaf1319b6265e6ef37ca268247052f0b5cac91d14800c1b6f8cb23a28f4620aa0a8e12de88906ec5755a4a643917947a010b7bf'),
    dict(password = 'password', salt = 'salt', N = 128, r = 3, p = 3, dkLen = 45, result = 'bdbefc353d2145625af2d8f86dad13d6bd993daabbb39a740887ff985803a22675284ad4c3ab5f68a779d0b71a'),
    dict(password = 'password', salt = 'salt', N = 256, r = 6, p = 2, dkLen = 100, result = '08d4bd8bc6a0db2d3afb86e14bb3e219c7e067add953576ebc4678f86c85f5bc819de1fe22877c7d98c2ee11fef9f3a1ca0047a079b3ee35152c31d51b8db57f267050255065b933d65edfc65203e9b964c5c54507eba8b990c8c9106274fa105237550a'),
    dict(password = "You're a master of Karate", salt = 'And friendship for Everyone', N = 1024, r = 1, p = 1, dkLen = 256, result = '3a3cbca04456f6ee5295460171a2a2b27e1c28163999f19ab1e2eeda01e355d904627c6baa185087f99f3fee33e4a9ccad1f4230681d77301d2b4f6543023e090faf6e86431a1071f64b693402ceb485469ef33308af104fb1f87b39ecaf733ebc3d73b184c0914fbc4e8eff90777c60172596de79070418f3c9998b6b60640f1d8f3019904b3e20f2920d26c21daf81d0652ffcaffccf734773e0730900204b56b5bebbfb8c3a31d543f6e3ac5f4e1431a864da87c239eefec8e462d458ee2d214646864e9207e15f66a3782b52bb5158152d757d0ca25d2062235ee76c431e5016b3a52cd5b575e3a26aba95654d5b9a991527f5a19d7275ac4f9889081ee9'),
]

# Use the C wrapper to help generate results against a known-correct implementation
if False:
    import scrypt

    for test in Tests:
        test = test.copy()
        test['buflen'] = test['dkLen']
        del test['dkLen']
        del test['result']
        print scrypt.hash(**test).encode('hex')
        print

# Run each test case
index = 0
for test in Tests:
    index += 1

    # Store and remove the expected result
    result = test['result']
    del test['result']

    # Perform the hash
    h = pyscrypt.hash(**test).encode('hex')

    # How'd we do?
    print "Test %d: %s" % (index, { True: "pass", False: "FAIL" }[h == result])
