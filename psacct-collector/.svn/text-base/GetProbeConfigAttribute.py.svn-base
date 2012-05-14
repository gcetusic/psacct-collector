#!/usr/bin/env python

import sys
import GratiaCore
import getopt
import xml.sax.saxutils

def usage():
    print """usage: GetProbeConfigAttribute [-h|--help]
       GetProbeConfigAttribute [-c <probeconfig>|--conf=<probeconfig>] <attribute> ...""" 

def main():
    GratiaCore.quiet = 1

    customConfig = None;
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hc:l:", ["help", "conf="])

    except getopt.GetoptError:
        usage()
        sys.exit(2)

    for o, a in opts:
        if o in ["-h", "--help"]:
            usage()
            sys.exit()
                
        if o in ["-c", "--conf"]:
            customConfig = a

    if customConfig:
        Config = GratiaCore.ProbeConfiguration(customConfig)
    else:
        Config = GratiaCore.ProbeConfiguration()
    
    for attribute in args:
        try:
            print Config.getConfigAttribute(attribute)
        except xml.parsers.expat.ExpatError:
            sys.exit(1)
        except:
            sys.stderr.write("Problem reading config attribute " + attribute +
                             ": " + str(sys.exc_info()[1]) + "\n")
            sys.exit(1)

if __name__ == "__main__":
    main()
