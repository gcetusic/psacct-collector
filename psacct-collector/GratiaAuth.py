#!/usr/bin/python

from kerberos import *
import couchdb
import httplib
import optparse

def getServer(hostname=None, port=None, dbtype=None):
    if dbtype == 'couchdb':
        connection = couchdb.Server('http://' + hostname + ':' + port)
	return connection
    if dbtype == 'mongodb':
	connection = pymongo.Connection(hostname, port)
	return server

def getDatabase(conn=None, dbtype=None, dbname=None):
    if dbtype == 'couchdb':
	try:
            __connection__ = conn.create(dbname)
	except couchdb.PreconditionFailed:
	    pass
	__connection__ = conn[dbname]
	return __connection__

def kerbAuth(conn=None, service='host', hostname='localhost', dbtype='couchdb'):
    # setup kerberos
    try:
        status, ctx = authGSSClientInit('%s@%s' % (service, hostname), gssflags=GSS_C_DELEG_FLAG|GSS_C_MUTUAL_FLAG|GSS_C_SEQUENCE_FLAG)
        status = authGSSClientStep(ctx, '')
        token = authGSSClientResponse(ctx)
    except GSSError, e:
	#print "Could not do GSSAPI setp with continue: %s/%s" % (e[0][0], e[1][0])
	return None
    if token:
        if dbtype == 'couchdb':
	    conn.resource.headers = {'Authorization': 'Negotiate %s' % token }
	return conn
    else:
	return

    # Make http call
    resp = conn.getresponse()
    if resp.status != 200:
        print "Error: %s" % str(resp.status)

    # Check for kerb header
    krb_reply = resp.getheader('WWW-Authenticate')
    if not krb_reply:
        print "Server did not send kerberos reply"

    # print html contents
    print resp.read()

if __name__=='__main__':
    parser = optparse.OptionParser()
    parser.add_option('-p', '--port', type='int', default=80, help='Port for the client to connect to.')
    parser.add_option('-n', '--hostname', help='FQDN of the server to authenticate with.')
    parser.add_option('-m', '--message', help='Message to send from the client to the server', default='Kerberos is working')
    parser.add_option('-s', '--service', help='Name of service for client to access', default='host')
    #parser.add_option('-6', '--ipv6', action='store_true', help='Use IPv6')
    #parser.add_option('-c', '--ccache', help='Location of the credentials cache')

    opts, args = parser.parse_args()

    if not opts.hostname:
        parser.error('You must specify the FQDN servername')

    # setup http connection
    try:
        conn = httplib.HTTPConnection(opts.hostname, opts.port)
        conn.connect()
    except:
       print "Could not connect to %s:%s" % (hostname, port)

    kerbauth(service=opts.service, hostame=opts.hostname, port=opts.port, data=opts.message)

