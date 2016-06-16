# About

These scripts will help you hack the swipe lock pattern of an Android device. The scripts work on the hash file gesture.key from an
Android device.  You'll have to get that file through a root exploit or other means to recover the swipe lock pattern.

Android_GestureFinder.py and GenerateAndroidGestureRainbowTable.py are written by Arun Prasannan and Alex Caithness of CCL Forensics.

GestureKeyLookup.py written by Joshua Wright.

# HOWTO

1. Precompute lookup database file. You only have to do this once:
```
$ python3 GenerateAndroidGestureRainbowTable.py
2016-06-16 15:03:45.620806: Building hashes for patterns with length 3
2016-06-16 15:03:45.625866: Building hashes for patterns with length 4
2016-06-16 15:03:45.658979: Building hashes for patterns with length 5
2016-06-16 15:03:45.879143: Building hashes for patterns with length 6
2016-06-16 15:03:47.436660: Building hashes for patterns with length 7
2016-06-16 15:03:57.381887: Building hashes for patterns with length 8
2016-06-16 15:05:06.871813: Building hashes for patterns with length 9
```

2. Download the gesture.key file from the Android device:
```
$ adb pull /data/system/gesture.key
4 KB/s (20 bytes in 0.004s)
```

3. Recover swipe lock pattern:
```
$ cd PatternLockScripts/
$ python GestureKeyLookup.py /path/to/gesture.key
[0, 1, 3, 4, 5, 8]
```

The decoded value is in this pattern:

0  1  2
3  4  5
6  7  8


# Questions, comments, concerns?

Joshua Wright
jwright@willhackforsushi.com
