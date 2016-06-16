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

import hashlib
import sqlite3
import array
import os.path as path
import datetime

__version__ = "1.0.0"
__description__ = "Builds the rainbow table for breaking the Android gesture lock hash."
__contact__ = "Alex Caithness"

# Constants
MAX_VALUE = 8
SQLITE_DB = "AndroidLockScreenRainbow.sqlite"

# returns bool (more to come), int (next index to increment)
def incr(current_pattern, index):
    #print(current_pattern)
    if index > len(current_pattern) - 1: raise ValueError("Index out of range")
    if index < 0 : return False, 0
    if current_pattern[index] == MAX_VALUE:
        current_pattern[index] = 0
        return incr(current_pattern, index - 1)
    else:
        current_pattern[index] += 1
        if index == len(current_pattern) - 1:
            return True, index
        else:
            #current_pattern[index + 1] = 0
            return True, len(current_pattern) - 1
        
    

def generate_pattern(length):
    current_pattern = [i for i in range(0,length)]
    yield current_pattern
    more_to_come = True
    index = length - 1

    while more_to_come:
        more_to_come, index = incr(current_pattern, index)
        # Check it only contains unique
        is_valid = True
        for i in range(len(current_pattern) - 1):
            if current_pattern[i] in current_pattern[i + 1:]:
                is_valid = False
                break
        if is_valid: yield current_pattern


def main():
    if path.exists(SQLITE_DB):
        print("The database file \'{0}\' already exists, exiting...".format(SQLITE_DB))
        exit()

    # Setup Database
    conn = sqlite3.connect(SQLITE_DB)
    conn.execute("CREATE TABLE RainbowTable (hash primary key, pattern);")
    
    with conn:
        for length in range(3,10):
            print(str(datetime.datetime.now()) + ": Building hashes for patterns with length " + str(length))
            for pattern in generate_pattern(length):
                #print(pattern)
                my_bytes = array.array("B", pattern).tobytes()
                sha1hasher = hashlib.sha1()
                sha1hasher.update(my_bytes)
                conn.execute("INSERT INTO RainbowTable VALUES (?,?);", (sha1hasher.hexdigest(), str(pattern)))

    conn.execute("VACUUM;")
    conn.close()


if __name__ == "__main__":
    main()
