#! /usr/bin/python

from kerberos import *
import couchdb
import httplib
import optparse
import pprint
import sys
import bisect
import pdb

def getServer(hostname=None, port=None, dbtype='couchdb'):
    if dbtype == 'couchdb':
        connection = couchdb.Server('http://' + hostname + ':' + str(port))
	return connection
    if dbtype == 'mongodb':
	connection = pymongo.Connection(hostname, port)
	return server

def getDatabase(conn=None, dbtype=None, dbname=None):
    if dbtype == 'couchdb':
	try:
	    __connection__ = conn[dbname]
	    return __connection__
        except:
            sys.exit("Could not connect to database %s" % dbname)
def kerbAuth(conn=None, service='host', hostname='localhost', dbtype='couchdb'):
    try:
        status, ctx = authGSSClientInit('%s@%s' % (service, hostname), gssflags=GSS_C_DELEG_FLAG|GSS_C_MUTUAL_FLAG|GSS_C_SEQUENCE_FLAG)
        status = authGSSClientStep(ctx, '')
        token = authGSSClientResponse(ctx)
    except GSSError, e:
	sys.exit("Could not do GSSAPI setp with continue: %s/%s" % (e[0][0], e[1][0]))
    if token:
        if dbtype == 'couchdb':
	    conn.resource.headers = {'Authorization': 'Negotiate %s' % token }
	return conn
    else:
	return sys.exit("Missing Kerberos token while trying to connect...")

def flatten(values):
  def rflat(seq2):
    seq = []
    for entry in seq2:
        if '__contains__' in dir(entry) and \
                     type(entry) != str and \
                     type(entry)!=dict:
            seq.extend([i for i in entry])
        else:
            seq.append(entry)
    return seq

  def seqin(values):
    for i in values:
        if '__contains__' in dir(i) and \
                     type(i) != str and \
                     type(i) != dict:
            return True
    return False

  seq = values[:]
  while seqin(seq):
      seq = rflat(seq)
  times = sorted(seq)
  return times

## Summaries
# users
def usersTotalActivity(database, user=None, machine=None, command=None, startTime=0, endTime=2147483647):
    # What was the first and last time the user was active?
    view = database.view("users/activity", group_level=1)
    users = {}
    if user:
        result = view[[user]:[user, {}]]
    else:
        result = view
    for row in result.rows:
        key = row.key[0]
        times = row.value
        users.setdefault(key, []).append(times)
    return users

def usersTotalActivityPerMachine(database, user=None, machine=None, command=None, startTime=0, endTime=2147483647):
    # When was the first and last time the user was active on a machine?
    view = database.view("users/activity", group_level=2)
    users = {}
    if user:
        if machine:
            result = view[[user, machine]:[user, machine]]
        else:
            result = view[[user]:[user, {}]]
    else:
        result = view
    for row in result.rows:
        key = tuple(row.key)
        times = row.value
        users.setdefault(key, []).append(times)
    return users

def usersMachineActivity(database, user=None, machine=None, command=None, startTime=0, endTime=2147483647):
    # On which machines was the user active?
    view = database.view("users/machines", group_level=2)
    users = {}
    if user:
        result = view[[user]:[user, {}]]
    else:
        result = view
    for row in result.rows:
        key = row.key[0]
        machine = row.key[1]
        users.setdefault(key, []).append(machine)
    return users

# machines
def machinesUsers(database, user=None, machine=None, command=None, startTime=0, endTime=2147483647):
    # Which users were active on this machine?
    view = database.view("machines/users", group_level=1)
    machines = {}
    if machine:
        result = view[machine]
    else:
        result = view
    for row in result.rows:
        key = row.key
        users = row.value
        machines.setdefault(key, []).append(users)
    return machines

## Records
# users
def usersCommands(database, user=None, machine=None, command=None, startTime=0, endTime=2147483647):
    # Which commands did the user execute?
    view = database.view("users/commands", group_level=1)
    commands = {}
    if user:
        result = view[[user]:[user, {}]]
    else:
        result = view
    for row in result.rows:
        key = row.key[0]
        times = row.value
        commands.setdefault(key, []).append(times)
    return commands

def usersCommandsPerMachine(database, user=None, machine=None, command=None, startTime=0, endTime=2147483647):
    # Which commands did the user execute on a machine?
    view = database.view("users/commands", group_level=2)
    commands = {}
    if user:
        if machine:
            result = view[[user, machine]:[user, machine]]
        else:
            result = view[[user]:[user, {}]]
    else:
        result = view
    for row in result.rows:
        key = tuple(row.key)
        times = row.value
        commands.setdefault(key, []).append(times)
    return commands

def usersActivityTimePerMachine(database, user=None, machine=None, command=None, startTime=0, endTime=2147483647):
    # On which machines was this user active between X and Y?
    view = database.view("users/machineactivity", group_level=2)
    users = {}
    if machine:
        result = view[[machine]:[machine, {}]]
    else:
        result = view
    for row in result.rows:
        key = row.key[0]
        times = map(int, map(float, row.value))
        times = sorted(set(times))
        insleft = bisect.bisect_left(times, startTime)
        insright = bisect.bisect_right(times, endTime)
        if not (insleft==len(times)):
            if insleft != insright:
                users.setdefault(key, []).append(row.key[1])
    return users

# machines
def machinesActivityTimePerUser(database, user=None, machine=None, command=None, startTime=0, endTime=2147483647):
    # Which users were active on this machine between X and Y?
    if startTime>endTime:
        sys.exit("startTime should be smaller than endTime")
    view = database.view("machines/useractivity", group_level=2)
    users = {}
    if machine:
        result = view[[machine]:[machine, {}]]
    else:
        result = view
    for row in result.rows:
        key = row.key[0]
        times = map(int, map(float, row.value))
        times = sorted(set(times))
        insleft = bisect.bisect_left(times, startTime)
        insright = bisect.bisect_right(times, endTime)
        if not (insleft==len(times)):
            if insleft != insright:
                users.setdefault(key, []).append(row.key[1])
    return users

# commands
def commandsExecutionTimes(database, user=None, machine=None, command=None, startTime=0, endTime=2147483647):
    # Where were these commands executed, by whom at what time?
    view = database.view("commands/exectimes")
    commands = {}
    if command:
        result = view[[command]:[command, {}]]
    else:
        result = view
    for row in result.rows:
        key = tuple(row.key[0:3])
        time = row.key[3]
        commands.setdefault(key, []).append(time)
    return commands

if __name__=='__main__':
    parser = optparse.OptionParser()
    parser.add_option('-p', '--port', type='int', default=80, help='Port for the client to connect to.')
    parser.add_option('-n', '--hostname', help='FQDN of the server to authenticate with.')
    parser.add_option('-s', '--service', help='Name of Kerberos service for client to access', default='host')
    parser.add_option('-d', '--database', help='Database for executing queries')
    parser.add_option('-u', '--user', help='name of user to search information for')
    parser.add_option('-m', '--machine', help='Name of machine to search information for')
    parser.add_option('-q', '--query', help='Query function to execute')
    parser.add_option('-c', '--command', help='Command name')
    parser.add_option('-t', '--time', help='Time range to query for activity. Format is unixtimestamp:unixtimestamp', default='0:2147483647')
    #parser.add_option('-6', '--ipv6', action='store_true', help='Use IPv6')
    #parser.add_option('-c', '--ccache', help='Location of the credentials cache')

    opts, args = parser.parse_args()

    if not opts.hostname:
        parser.error('You must specify the FQDN servername.')

    if not opts.database:
        parser.error('Which database should I connect to?')

    if not opts.query:
        parser.error('You need to provide a query function name because printing *everything* is not an option!')

    if opts.time:
        range = opts.time.split(':')
        if not len(range) == 0:
            startTime = int(range[0])
        if len(range) > 1:
            endTime = int(range[1])
        else:
            endTime = 2147483647

    server = getServer(opts.hostname, opts.port, 'couchdb')
    connection = kerbAuth(conn=server, service=opts.service, hostname=opts.hostname)
    database = getDatabase(connection, 'couchdb', opts.database)

    pp = pprint.PrettyPrinter(indent=2)
    pp.pprint(locals()[opts.query](database=database, user=opts.user, machine=opts.machine, command=opts.command, startTime=startTime, endTime=endTime))

