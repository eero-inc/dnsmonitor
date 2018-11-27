#!/usr/bin/env python3
# This only exists because xxd is a pain to install in this setup.
import sys
from binascii import b2a_base64
import hashlib


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            sha256.update(block)
    return b2a_base64(sha256.digest()).strip().decode("utf-8")


if __name__ == "__main__":
    fname = sys.argv[1]
    print("======================================")
    print("New pkg hash: ", sha256_checksum(fname))
