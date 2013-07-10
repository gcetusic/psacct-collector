#!/usr/bin/env python
 
from PSACCTProbeLib import PsAcct
import sys
import pdb
if __name__ == '__main__':
    if hasattr(sys,'argv') and '--help' in sys.argv:
        print "Usage: "+sys.argv[0]+" [--process-only] [--help]"
        sys.exit(0)

    if hasattr(sys,'argv') and '--process-only' in sys.argv:
        PsAcct( enable = False )
    else:
        PsAcct()
