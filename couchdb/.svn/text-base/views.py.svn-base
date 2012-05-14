## Author: Goran Cetusic
## Email: goran.cetusic@gmail.com, goran.cetusic@cern.ch
## Description: These are the CouchDB views for CERN lxbatch process accounting.

# Users active on machine are X,Y,Z...
# Database: summaries
# View: machines/users
def fun(doc):
  if doc["ProbeName"] and doc["UserID"]:
    yield doc["ProbeName"], doc["UserID"]["LocalUserId"]

def fun(keys, values):
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
  users = sorted(seq)
  set = {}
  map(set.__setitem__, users, [])
  return set.keys()

# User was active on machines X,Y,Z... (summaries)
# Database: summaries
# View: users/machines
def fun(doc):
  for record in doc["RecordData"]:
    yield [doc["UserID"]["LocalUserId"], doc["ProbeName"]], None

def fun(keys, values):
  return None

# User was active on machine X first time on Y and last time on Z
# Database: summaries
# View: users/activity
def fun(doc):
  for record in doc["RecordData"]:
    yield [doc["UserID"]["LocalUserId"], doc["ProbeName"]], [record["StartTime"], record["EndTime"]]
  
def fun(keys, values):
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
  return [times[0], times[-1]]

# User executed commands X,Y,Z... on machine W
# Database: records
# View: users/commands
def fun(doc):
  commands = []
  if doc["ProbeName"] and doc["RecordData"] and doc["UserID"]:
    for command in doc["RecordData"]:
      yield [doc["UserID"]["LocalUserId"], doc["ProbeName"]], command["JobName"]

def fun(keys, values):
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
  commands = sorted(seq)
  set = {}
  map(set.__setitem__, commands, [])
  return set.keys()

# User was active on machine X at times Y,Z,W...
# Database: records
# View: users/machineactivity
def fun(doc):
  commands = []
  for command in doc["RecordData"]:
    commands.append(command["StartTime"])
    commands.append(command["EndTime"])
  yield [doc["UserID"]["LocalUserId"], doc["ProbeName"]], commands

def fun(keys, values):
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
  set = {}
  map(set.__setitem__, seq, [])
  return sorted(set.keys())

# On machine X user Y was active at times Z,W...
# Database: records
# View: machines/useractivity
def fun(doc):
  commands = []
  for command in doc["RecordData"]:
    commands.append(command["StartTime"])
    commands.append(command["EndTime"])
  yield [doc["UserID"]["LocalUserId"], doc["ProbeName"]], commands

def fun(keys, values):
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
  set = {}
  map(set.__setitem__, seq, [])
  return sorted(set.keys())

# Command was executed by user X on machine Y at time Z (records)
# View: commands/exectimes
def fun(doc):
  if doc["ProbeName"] and doc["RecordData"] and doc["UserID"]:
    for command in doc["RecordData"]:
      yield [command["JobName"], doc["UserID"]["LocalUserId"], doc["ProbeName"], command["StartTime"]], None
