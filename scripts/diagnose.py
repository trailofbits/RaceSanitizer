#!/usr/bin/env python

import os
import subprocess
import sys

DEVNULL = open("/dev/null", "wb")

with open(sys.argv[1], 'r') as lines:
  for line in lines:
    if line.startswith("\t\t") and ":" in line:
      line = line.strip("\0")
      binary, offset = line.strip("\t\n ").split(":")
      if os.path.exists(binary):
        try:
          output = subprocess.check_output(["addr2line", "-e", binary, "-a", offset], stderr=DEVNULL)
          print "\t\t", output.rstrip("\n").split("\n")[1]
          #print "\t\t\t", line.strip("\t\n ")
          continue
        except:
          pass
    print line.rstrip()