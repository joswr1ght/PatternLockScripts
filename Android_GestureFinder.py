#!/usr/bin/env python3

"""
Copyright (c) 2011, CCL Forensics
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the CCL Forensics nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CCL FORENSICS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import os
import sys
from binascii import hexlify
import re
import hashlib
import sqlite3

__contact__ = "Arun Prasannan, Alex Caithness"
__version__ = "1.1.0"
__description__ = "Locate potential Android lock patterns"


if len(sys.argv) != 2:
    print("Usage: " + os.path.basename(sys.argv[0]) + " <input>")
    sys.exit(2)

# Constants
CHUNK_SIZE = 2032
SKIP_SIZE  = 16
SQLITE_DB = "AndroidLockScreenRainbow.sqlite"

hasher = hashlib.sha1()
hasher.update(b"\xff" * CHUNK_SIZE)
black_page = hasher.hexdigest()

hasher = hashlib.sha1()
hasher.update(b"\x00" * CHUNK_SIZE)
white_page = hasher.hexdigest()

# basic check for the rainbow table database
if not os.path.isfile(SQLITE_DB):
    print("The rainbow table database {0} could not be found.".format(SQLITE_DB))
    sys.exit(1)

conn = sqlite3.connect(SQLITE_DB)
cur = conn.cursor()

results = []

regex = re.compile(b".{20}\x00{" + str(CHUNK_SIZE - 20).encode("ascii") + b"}", re.DOTALL)

with open(sys.argv[1], "rb") as f:
    chunk = 1
    while chunk:
        chunk = f.read(CHUNK_SIZE)

        # hash the chunk to weed out blank pages
        hasher = hashlib.sha1()
        hasher.update(chunk)
        this_page_hash = hasher.hexdigest()

        if this_page_hash == black_page or this_page_hash == white_page:
            f.seek(SKIP_SIZE, os.SEEK_CUR)
            continue

        if regex.match(chunk) is not None:
            lookup_hash = hexlify(chunk[:20]).decode()

            # look up hash in database
            cur.execute("SELECT pattern FROM RainbowTable WHERE hash = ?", (lookup_hash,))

            result = cur.fetchone()
            if result:
                # offset, hash, pattern
                results.append([f.tell() - CHUNK_SIZE, lookup_hash, result[0]])

        f.seek(SKIP_SIZE, os.SEEK_CUR)

conn.close()

# print the results: offset, hash and pattern (tab-delimited)
if results:
    print("\t".join(["Offset".ljust(10), "Hash".ljust(40), "Pattern"]))
    for result in results:
        print("\t".join(["{0:10d}".format(result[0]), result[1], result[2]]))
else:
    print("No lock patterns found in {0}.".format(sys.argv[1]))

