pyscrypt
========

A very simple, pure-Python implementation of the scrypt password-based key derivation function with no dependencies beyond standard Python libraries.



API
---

```python
import pyscrypt

hashed = pyscrypt.hash(password = "correct horse battery staple", 
                       salt = "seasalt", 
                       N = 1024, 
                       r = 1, 
                       p = 1, 
                       dkLen = 256)
print hashed.encode('hex')
```



Test Harness
------------

A handful of test cases are provided, if you run the library from the command line, it will iterate over them indicating pass/fail.

    # python pyscrypt.py
    Test 1: pass
    Test 2: pass
    Test 3: pass
    Test 4: pass
    Test 5: pass                                                                                                                                              



FAQ
---

**Why is this so slow?**
It is written in pure Python. It is not meant to be fast, more of a reference solution.

On my MacBook Air, I get around 3,000 hashes/s using a C-wrapper while I get around 2 hashes/s using this implementation.

**How do I get one of these C wrappers you speak of?**

    > # Download the source
    > curl -L https://github.com/forrestv/p2pool/archive/13.4.tar.gz > p2pool-13.4.tar.gz

    > # Untar
    > tar -xzf p2pool-13.4.tar.gz
    
    > # Build and install
    > cd p2pool-13.4/litecoin_scrypt/
    > python setup.py build
    > sudo python setup.py install

    > python
    >>> import scrypt
    >>> scrypt.hash(password = "correct horse staple battery", salt = "seasalt", N = 1024, p = 1, r = 1, buflen = 256)
    
**How do I get a question I have added?**
E-mail me at me@ricmoo.com with any questions, suggestions, comments, et cetera.

**Can I give you my money?**
Umm... Ok? :-)

_Bitcoin_  - `1LNdGsYtZXWeiKjGba7T997qvzrWqLXLma`
_Litecoin_ - `LXths3ddkRtuFqFAU7sonQ678bSGkXzh5Q`
_Namecoin_ - `N6JLCggCyYcpcUq3ydJtLxv67eEJg4Ntk2`

