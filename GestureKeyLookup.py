#!/usr/bin/env python3
import sys

"""
Copyright (c) 2013 Joshua Wright <jwright@hasborg.com>

Use the CCL Forensics AndridLockScreenRainbow.sqlite file, and a gesture.key
file to look up the numeric swipe pattern.
"""

import hashlib
import sqlite3    
import binascii
import os.path as path

__version__ = "1.1.0"
__description__ = "Reads from a gesture.key file and searches for hash in AndroidLockScreenRainbow.sqlite"
__contact__ = "Joshua Wright <jwright@hasborg.com>"

# Constants
MAX_VALUE = 8
SQLITE_DB = "AndroidLockScreenRainbow.sqlite"
GESTURE_KEY = "gesture.key"


def main():
    if len(sys.argv) == 1:
        keyfile="gesture.key"
    else:
        keyfile=sys.argv[1]

    if not path.exists(SQLITE_DB):
        print("Cannot find the database file \'{0}\', exiting...".format(SQLITE_DB))
        exit()

    if not path.exists(keyfile):
        print("Cannot find the gesture file \'{0}\', exiting...".format(keyfile))
        exit()

    with open(keyfile, mode='rb') as file:
        fileContent = file.read()
        hash=binascii.hexlify(fileContent).decode()

    # Setup Database
    conn = sqlite3.connect(SQLITE_DB)
    cur = conn.cursor()
    cur.execute("SELECT pattern FROM RainbowTable WHERE hash=\"" + hash + "\"")
    
    pattern = cur.fetchone()
    if pattern is not None:
        print(pattern[0])
    else: 
        print("Pattern not found in the gesture.key file.  Make sure this is a valid\ngesture.key file, and that the AndroidLockScreenRainbow.sqlite file is\npopulated.")
    conn.close()


if __name__ == "__main__":
    main()
