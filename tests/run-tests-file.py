import sys
sys.path += '..'

import os

import cStringIO as StringIO

import pyscrypt
from pyscrypt import ScryptFile

print "Version:", ".".join(str(p) for p in pyscrypt.VERSION)

# Test decrypted output is equal to the input
for text_length in [3, 16, 127, 128, 129, 1500]:
    plaintext = os.urandom(text_length)

    # Encrypt the text to memory
    fp = StringIO.StringIO()
    sf = ScryptFile(fp = fp, password = "password", N = 1024, r = 1, p = 1, mode = 'w')
    sf.write(plaintext)
    sf.finalize()
    fp.seek(0)
    crypttext = fp.getvalue()
    fp.close()

    # Decrypt the text from memory
    fp = StringIO.StringIO(crypttext)
    sf = ScryptFile(fp = fp, password = "password", mode = 'r')
    decrypted = sf.read()
    sf.close()

    result = {True: "pass", False: "fail"}[decrypted == plaintext]
    print "Test Encrypt/Decrypt: text_length=%s result=%s valid=%s" % (text_length, result, sf.valid)


# Generate some files to make sure the tarsnap scrypt utility can read them
for length in (10, 100, 1000):
    path_scrypt = '/tmp/test-%d.scrypt' % length
    path_text = '/tmp/test-%d.txt' % length
    text = "Hello world" * length
    sf = ScryptFile(file(path_scrypt, 'w'), "password", 1024, 1, 1)
    sf.write(text)
    sf.close()
    file(path_text, 'w').write(text)
    print "Created %s and %s. Check with tarsnap." % (path_scrypt, path_text)

# Open some files created with the tarsnap utility and read them
for filename in ('test1', 'test2'):
    path_scrypt = os.path.join('tests/', filename + '.scrypt')
    path_text = os.path.join('tests/', filename + '.txt')

    valid = ScryptFile.verify_file(file(path_scrypt), 'password')
    result = {True: "pass", False: "fail"}[valid]
    print "Test Verify: filename=%s result=%s" % (path_scrypt, result)

    for test in (0, 1, 2):
        sf = ScryptFile(file(path_scrypt), 'password')
        f = file(path_text)

        # Test small read (smaller than a block)
        if test == 0:
            content_scrypt = sf.read(5)
            content_text = f.read(5)

        # Test large read (larger than a block)
        elif test == 1:
            content_scrypt = sf.read(1005)
            content_text = f.read(1005)

        # Test full read
        elif test == 2:
            content_scrypt = sf.read()
            content_text = f.read()

        result = {True: "pass", False: "fail"}[content_scrypt == content_text]
        print "Test Decrypt: dec(%r) == %r result=%s valid=%s" % (path_scrypt, path_text, result, sf.valid)
