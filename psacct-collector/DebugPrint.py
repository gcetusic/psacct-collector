#!/usr/bin/env python

"""
DebugPrint.py
   Utility to add text to the Gratia log file

   usage: DebugPrint.py [-h|--help]
       DebugPrint.py [-l #|--level=#] [-c <probeconfig>|--conf=<probeconfig>] <message>
       cat message.txt | DebugPrint.py [-l #|--level=#] [-c <probeconfig>|--conf=<probeconfig>]
"""

import sys
import GratiaCore
import getopt
import string

def Usage():
    """
    Print the usage.
    """
    print """usage: DebugPrint.py [-h|--help]
       DebugPrint.py [-l #|--level=#] [-c <probeconfig>|--conf=<probeconfig>] <message>
       cat message.txt | DebugPrint.py [-l #|--level=#] [-c <probeconfig>|--conf=<probeconfig>]"""

def main():
    """
    Body of DebugPrint
    """
    level = 0
    customConfig = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hc:l:", ["help", "conf=" , "level="])

    except getopt.GetoptError:
        Usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ["-h", "--help"]:
            Usage()
            sys.exit()

        if opt in ["-c", "--conf"]:
            customConfig = arg

        if opt in ["-l", "--level"]:
            level = int(arg)

    GratiaCore.quiet = 1

    if customConfig:
        GratiaCore.Config = GratiaCore.ProbeConfiguration(customConfig)
    else:
        GratiaCore.Config = GratiaCore.ProbeConfiguration()

    GratiaCore.quiet = 0

    if len(args) > 0:
        GratiaCore.DebugPrint(level, string.join(args, " ").rstrip())
    else:
        while 1:
            try:
                line = raw_input()
            except EOFError, ex:
                break
            GratiaCore.DebugPrint(level, line.rstrip())


if __name__ == "__main__":
    main()
