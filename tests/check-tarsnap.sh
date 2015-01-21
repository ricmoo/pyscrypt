#!/bin/bash

scrypt dec /tmp/test-10.scrypt /tmp/test-10.dec.txt
diff /tmp/test-10.dec.txt /tmp/test-10.txt 

scrypt dec /tmp/test-100.scrypt /tmp/test-100.dec.txt
diff /tmp/test-100.dec.txt /tmp/test-100.txt 

scrypt dec /tmp/test-1000.scrypt /tmp/test-1000.dec.txt
diff /tmp/test-1000.dec.txt /tmp/test-1000.txt 

