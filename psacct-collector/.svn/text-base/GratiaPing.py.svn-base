#!/bin/env python

#@(#)gratia/probe/common:$HeadURL: https://gratia.svn.sourceforge.net/svnroot/gratia/trunk/probe/common/GratiaPing.py $:$Id: GratiaPing.py 4068 2010-06-07 19:32:45Z pcanal $

import getopt,sys
import GratiaCore

class UsageError(Exception):
    def __init__(self, msg):
        self.msg = msg

def Usage():
        print" Usage: "+sys.argv[0]+" [-v] [--verbose]"
        print
        print "   -v, --verbose: print the result in human readable form"
        print 
        print " This will attempt to upload a handshake to the server"
        
if __name__ == '__main__':
        verbose = False;
        argv = sys.argv
        try:
                try:
                        opts, args = getopt.getopt(argv[1:], "hv", ["help","verbose"])
                except getopt.error, msg:
                        raise UsageError(msg)
        except UsageError, err:
                print >>sys.stderr, err.msg
                print >>sys.stderr, "for help use --help"
                sys.exit(2)
        for o, a in opts:
                if o in ("-v","--verbose"):
                        verbose = True;
                if o in ("-h","--help"):
                        Usage()
                        sys.exit(0)

        rev = "$Revision: 4068 $"
        GratiaCore.RegisterReporter("GratiaPing.py",GratiaCore.ExtractSvnRevision(rev))

        GratiaCore.Initialize()

        if (verbose):
                print "Number of successful handshakes: "+str(GratiaCore.successfulHandshakes)
        sys.exit(0==GratiaCore.successfulHandshakes)

