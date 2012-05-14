#
# Rewritten by: Goran Cetusic
# Email: goran.cetusic@gmail.com, goran.cetusic@cern.ch, goran.cetusic@kset.org
# Organization: CERN, IT-PES-PS
# Project: Openlab Summer Student Programme
# Original author:  Tim Byrne for the Open Science Grid
#


import sys, os, commands, time, shutil, glob, struct, Gratia, pwd, string, socket, re
from Gratia import DebugPrint, Send, Error

import traceback
from decimal import *

# System type constants
TYPE_AIX   = 0
TYPE_IRIX  = 1
TYPE_IRIX5 = 2
TYPE_IRIX6 = 3
TYPE_SUNOS = 4
TYPE_OSF1  = 5
TYPE_LINUX = 6

class SystemInfo:
    "Class use to handle the system specific information"
    
    ClkTck = os.sysconf("SC_CLK_TCK");
    Hostname = socket.getfqdn()
    Model = commands.getoutput("cat /proc/cpuinfo | grep 'model name' | head -1").split(':')[1].strip()
    Ncpu = commands.getoutput("grep -c processor /proc/cpuinfo")
    PSACCTTypeCode = ""
    StructFormat = "i8s8f4H116s"
    StructSize = 168
    Indices = { 'Cmd':0,'CpuUser':1,'CpuSys':2,'Wall':3,'uid':4,'gid':5,'Mem':6,'Disk':-1,'Start':7 }
    Users = {}

    def __init__(self):
        self.GetPSACCTTypeCode()
    
    #
    # Seconds
    #
    # Return the number of seconds corresponding to a number of clock ticks.
    #
    # Parameters:
    #   numberOfTicks - the number of ticks to convert
    #
    # Return:
    #   corresponding number of seconds.
    #
    def Seconds(self,numberOfTicks):
        getcontext().prec = 2
        seconds = Decimal(str(numberOfTicks / float(self.ClkTck)))
        return seconds

    #
    # GetPSACCTTypeCode
    #
    #  Get PSACCT Type Code will determine the PSACCT type for the current system and return a code to indicate
    #   the type.
    #
    #  Return:
    #    A code that represents each PSACCT Type
    #
    def GetPSACCTTypeCode(self):
        try:
            systemType = os.uname()[0]
        except:
            raise Exception("Could not determine the system type. ")

        # In the following if statement we should also set the structFormat
        # and structSize
        if systemType == "AIX":
            self.PSACCTTypeCode = TYPE_AIX
        elif systemType == "IRIX":
            self.PSACCTTypeCode = TYPE_IRIX
        elif systemType == "IRIX5":
            self.PSACCTTypeCode = TYPE_IRIX5
        elif systemType == "IRIX6":
            self.PSACCTTypeCode = TYPE_IRIX6
        elif systemType == "SunOS":
            self.PSACCTTypeCode = TYPE_SUNOS
        elif systemType == "OSF1":
            self.PSACCTTypeCode = TYPE_OSF1
        elif systemType == "Linux":
            self.PSACCTTypeCode = TYPE_LINUX
        else:
            print "missing type"
            #raise UnknownSystemTypeException("System type of " + systemType + " is not supported")        

        return self.PSACCTTypeCode

    #
    # Read 
    #
    # The following read methods will open the given PSACCT file path and read its contents into a dictionary of lists
    #  which represents all records per user.  Since each PSACCT Type may have a different
    #  file format, they each get their own read method so they can be customized appropriately.
    #
    # Parameters:
    #  PSACCTFileName - The full path to a PSACCT file, likely read from 'GetPSACCTFileNames'.
    #
    # Return:
    #  PSACCTRecords - A dictionary of lists representing the records read from the file, and each entity (field value) within
    #   each record...
    #
    def Read(self,PSACCTFileName):
        return Read(PSACCTFileName, self.StructFormat, self.StructSize)

    def GetUsername(self,uid):
        if self.Users.has_key(uid):
            return self.Users[uid]
        value = string.atoi(uid)
        try:
                username = pwd.getpwuid(value)[0]
        except:
                DebugPrint(0,"Warning the username was not found for uid="+uid)
                username = "uid="+uid
        self.Users[uid] = username
        return username

sysinfo = SystemInfo()
    
class Aggregate:
    JobName = "Unknown"
    CpuUserDuration = 0.0
    CpuSystemDuration = 0.0
    WallDuration = 0.0
    Username = "Unknown"
    Memory = 0.0
    Count = 0
    #Disk = 0.0
    StartTime = 0
    EndTime = 0
    Date = time.localtime()
    
    def __init__(self, record):
        # We parse the pacct record
        data = record  # record.split("|")
        self.JobName = re.sub(r'\s', '', data[sysinfo.Indices['Cmd']]) # Get rid of whitespaces
        self.CpuUserDuration = sysinfo.Seconds(string.atof(data[sysinfo.Indices['CpuUser']]))
        self.CpuSystemDuration = sysinfo.Seconds(string.atof(data[sysinfo.Indices['CpuSys']]))
        self.WallDuration = sysinfo.Seconds(string.atof(data[sysinfo.Indices['Wall']]))
        self.Memory = string.atof(data[sysinfo.Indices['Mem']])
        #Disk = string.atof(data[sysinfo.Indices['Disk']])
        getcontext().prec = 28
        StartTime_tuple = (time.strptime(data[sysinfo.Indices['Start']]))  # like Mon May 22 17:16:01 2006
        self.StartTime = Decimal(str(time.mktime(StartTime_tuple)))
        self.EndTime = self.StartTime + self.WallDuration
        EndTime_tuple = time.localtime(self.EndTime);

        self.Username = sysinfo.GetUsername(data[sysinfo.Indices['uid']])
        self.Count = 1

        # Reset the hours to midnight.
        #self.Date = time.struct_time((
        #    EndTime_tuple.tm_year,
        #    EndTime_tuple.tm_mon,
        #    EndTime_tuple.tm_mday,
        #    23, # EndTime_tuple.tm_hour,
        #    59, # EndTime_tuple.tm_min,
        #    59, # EndTime_tuple.tm_sec,
        #    EndTime_tuple.tm_wday,
        #    EndTime_tuple.tm_yday,
        #    EndTime_tuple.tm_isdst))

    def Add(self, other):
        # We accumulate an other record into this aggregate.
        #if (other.Username != self.Username):
        #    DebugPrint(0,"Non matching record " + self.Username + " vs. " + other.Username)
        #    return
        #if (other.Date != self.Date):
        #    DebugPrint(0,"Non matching date " + time.strftime("%a, %d %b %Y %H:%M:%S",self.Date)
        #         + " vs. " + time.strftime("%a, %d %b %Y %H:%M:%S",other.Date))
        self.JobName = "Summary"
        self.CpuUserDuration = self.CpuUserDuration + other.CpuUserDuration
        self.CpuSystemDuration = self.CpuSystemDuration + other.CpuSystemDuration

        self.WallDuration = self.WallDuration + other.WallDuration
        self.Count = self.Count + 1
        self.Memory = self.Memory + other.Memory
        if (self.StartTime > other.StartTime):
           self.StartTime = other.StartTime
        #self.Disk = self.Disk + other.Disk
        if (self.EndTime < other.EndTime):
           self.EndTime = other.EndTime

    def Key(self, type):
        return self.Username + "-" + str(self.Date[2]) + "-" + str(self.Date[1]) + "-" + str(self.Date[0]) + "-" + str(self.Date[3]) + ":" + type 
       
    #
    # Process
    #
    # The following process methods will take the record data read by the 'Read' method and turn it into a Gratia 
    #  'Usage Record' object.  Since each PSACCT type may have a different data format, they each get their own
    #  process method so they can be customized appropriately.
    #
    # Return:
    #  Usage Record - A Gratia Usage record populated with the data from the PSACCT record
    def Process(self):
        # We create a Gratia Record
        DebugPrint(5, "Processing record")

        usageRecord = Gratia.UsageRecord("RawCPU")
        usageRecord.LocalUserId(self.Username)
        usageRecord.JobName(self.JobName)
        usageRecord.CpuDuration(str(self.CpuUserDuration), "user")
        usageRecord.CpuDuration(str(self.CpuSystemDuration), "system")
        usageRecord.Memory(self.Memory / self.Count)
        #usageRecord.Disk(self.Disk / self.Count)
        usageRecord.StartTime(str(self.StartTime))
        usageRecord.EndTime(str(self.EndTime))
        #usageRecord.WallDuration(self.EndTime-self.StartTime, "")
        usageRecord.WallDuration(str(self.WallDuration), "")
        #usageRecord.Njobs(0)

        hostdesc = "model='"+sysinfo.Model+"' ncpu="+sysinfo.Ncpu
        #hostdesc = sysinfo.Model
        #usageRecord.Host(sysinfo.Hostname,True,hostdesc)
        #usageRecord.MachineName(sysinfo.MachineName)
 
        DebugPrint(5, "Done Processing")

        return usageRecord


class PsacctFiles:
    #
    # GetPSACCTFileNames
    #
    # Get PSACCT File Names will get a list of all PSACCT log files that need to be processed.  This list will
    #  contain the full paths to the pending PSACCT files.
    #
    # Parameters:
    #  probeConfig - A populated Probe Configuration object, likely loaded from 'ReadConfiguration'.
    #
    # Return:
    #  pendingFiles - A list of full paths for each PSACCT log file that needs to be processed.
    #
    def GetPSACCTFileNames(self,probeConfig):
        DebugPrint(5, "Getting pending PSACCT files")

        DataRepository = probeConfig.get_DataFolder()
        pendingFiles = []

        # Get the list of all files in the PSACCT File Repository
        DebugPrint(1, " Getting PSACCT files from " + DataRepository)
        files = glob.glob(DataRepository + "/spacct*")

        # Add each file to the pending files list if it doesn't already exist
        for f in files:
            if f not in pendingFiles and os.path.isdir(f) == False:
                DebugPrint(2, " Adding file to process list:  " + f)
                pendingFiles.append(f)       

        DebugPrint(1, " Pending files:  ", pendingFiles)
        DebugPrint(5, "Done getting pending PSACCT files")

        files = None

        return pendingFiles

    #
    # DisableLogrotate
    #
    # If /var/account/pacct is not empty, the default psacct logrotate will
    # delete it and more importantly reset the accounting to that file (hence
    # preventing us from collecting the data!)
    # 
    def DisableDefaultPsacct(self,probeConfig):

        # Prevent psacct logrotate from messing with us.
        defaultPsacctFile = "/var/account/pacct"
        if os.access(defaultPsacctFile, os.R_OK) and (os.path.getsize(defaultPsacctFile) != 0):

            #files = glob.glob("/var/account/pacct*gz")
            #for f in files:
            #    commands.getstatusoutput("gunzip " + f)

            #files = glob.glob("/var/account/pacct.*")
            #for f in files:
            #    target = os.path.join(probeConfig.get_DataFolder(),"s"+os.path.basename(f))
                #shutil.move(f,target)

            target = os.path.join(probeConfig.get_DataFolder(),"s"+os.path.basename(defaultPsacctFile))
            shutil.move(defaultPsacctFile,target)

            DebugPrint(3, "Write empty account file ("+defaultPsacctFile+") to disable psacct logrotate")
            emptyFile = open(defaultPsacctFile, "w")
            emptyFile.close()
 

    #
    # IsAccounting
    #
    # Is Accounting will test the given file to see if it is currently being logged to by an accounting process
    #
    # Parameters:
    #  PSACCTFileName - The file to check for accounting on
    #
    # Return:
    #  A boolean value indicating 'true' if the file is being accounting on and 'false' if it is not
    def IsAccounting(self,PSACCTFileName):
        DebugPrint(5, "Is accounting on " + PSACCTFileName + "?")

        isOn = False

        # TODO:  How to check if accton is running on the given file?
        # Well you can not

        DebugPrint(1, " Accounting on " + PSACCTFileName + ":  ", isOn)
        DebugPrint(5, "Done checking for is accounting on " + PSACCTFileName)

        return isOn

    #
    # StopAccounting
    #
    # Stop Accounting will stop the system's accounting process on the given file, assuming that accounting is
    #  actually running on that file.
    #
    # Parameters:
    #  PSACCTFileName - The name of the PSACCT log file to stop accounting on
    #
    def StopAccounting(self,PSACCTFileName):
        DebugPrint(5, "Stop accounting on " + PSACCTFileName)

        # Run ACCTON with no parameters to stop it
        commands.getstatusoutput("/usr/sbin/accton")

        DebugPrint(5, "Stopped accounting on " + PSACCTFileName)

    #
    # StartNewAccounting
    #
    # Start new accounting will restart the accounting process to a new, unique log file.
    #
    # Parameters:
    #  PSACCTFileNames - a list of file names on deck to be processed.  The new file name cannot be in this list.
    #
    def StartNewAccounting(self,PSACCTFileNames, probeConfig):
        DebugPrint(5, "Starting new accounting process")

        # Come up with a new file name that doesn't exist in the repository and append it to newAcctFile
        newAcctFile = probeConfig.get_PSACCTFileRepository() + time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
        while os.access(newAcctFile, os.R_OK):
            newAcctFile = probeConfig.get_PSACCTFileRepository() + time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())

        # Create the new file (but leave it empty)
        newFile = open(newAcctFile, "w")
        newFile.close()

        # Start accton on a new file
        commands.getstatusoutput("/usr/sbin/accton " + newAcctFile)

        self.DisableDefaultPsacct(probeConfig)
 
        DebugPrint(1, " New accounting log file: " + newAcctFile)
        DebugPrint(5, "Started new accounting process")

    #
    # MoveCurrentAccountingFile
    #
    # Move the current accounting file and restart the accounting process to a new, unique log file.
    #
    # Parameters:
    #  PSACCTFileNames - a list of file names on deck to be processed.  The new file name cannot be in this list.
    #
    def MoveCurrentAccountingFile(self,probeConfig):
        DebugPrint(5, "Moving current accounting files")

        repo = probeConfig.get_PSACCTFileRepository();
        DebugPrint(0, "Moving current accounting files to ",repo)
        if os.access(repo, os.R_OK) == False:
            Gratia.Mkdir(repo)
        
        AcctFile = os.path.join(probeConfig.get_PSACCTFileRepository(),"pacct")
        AcctFileStatus = os.path.join(probeConfig.get_PSACCTFileRepository(),"pacct.creation")

        cutoff = time.time() - (1 * 3600)
        
        if os.access(AcctFile, os.R_OK) and (os.path.getsize(AcctFile) != 0) and (not os.access(AcctFileStatus, os.R_OK) or os.path.getmtime(AcctFileStatus) < cutoff):
            # The file exists and is being used and is at least 1 hour old.
            target = probeConfig.get_DataFolder()
            if os.access(target, os.R_OK) == False:
                Gratia.Mkdir(target)
            prefix = os.path.join(target,"spacct-");
            copyFile = prefix + time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
            while os.access(copyFile, os.R_OK):
                copyFile = prefix + time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
            DebugPrint(0, "Moving current accounting files from "+AcctFile+" to "+copyFile)
            os.rename(AcctFile,copyFile)

        if not os.access(AcctFile, os.R_OK):
            # Create the new file (but leave it empty)
            newFile = open(AcctFile, "w")
            newFile.close()
            newFile = open(AcctFileStatus, "w")
            newFile.close()


        # Start accton on a new file
        res = commands.getstatusoutput("/usr/sbin/accton " + AcctFile)
        if res[0] != 0:
            Error("Could not enable accounting with log file: " + AcctFile+"res=",res)
        else:
            DebugPrint(1, "New accounting log file: " + AcctFile)

        self.DisableDefaultPsacct(probeConfig)

        DebugPrint(5, "Started new accounting process")

 
    #
    # Remove old backups
    #
    # Remove any backup older than the request number of days
    #
    # Parameters
    #   nDays - remove file older than 'nDays' (default 90)
    #
    def RemoveOldBackups(self, probeConfig, nDays = 90):
        backupDir = probeConfig.get_PSACCTBackupFileRepository()
        cutoff = time.time() - nDays * 24 * 3600

        DebugPrint(1, " Removing backup PSACCT files older than ", nDays, " days from " , backupDir)
 
        # Get the list of all files in the PSACCT File Backup Repository
        files = glob.glob(os.path.join(backupDir,"spacct")+"*")

        DebugPrint(3, " Will check the files: ",files)
        
        for f in files:
            if os.path.getmtime(f) < cutoff:
                DebugPrint(2, "Will remove: " + f)
                os.remove(f)
                
        files = None
        
    #
    # CanBackupFile
    # 
    # Can Backup File will ensure that the given file name will be able to be moved to the backup folder.  This is important
    #  to test BEFORE actually sending anything to Gratia so the application can be sure that it can move the processed
    #  PSACCT file to the backup folder after it is sent.  Not successfully moving the file to backup can result in the same
    #  PSACCT file being processed again.
    #
    # Parameters
    #  PSACCTFileName - 
    def CanBackupFile(self, PSACCTFileName, probeConfig):
        DebugPrint(5, "Checking if file can be backed up")

        canBackupFile = False

        # Create the backup directory if it doesn't exist
        if os.access(probeConfig.get_PSACCTBackupFileRepository(), os.R_OK) == False:
            Gratia.Mkdir(probeConfig.get_PSACCTBackupFileRepository())

        # Check if the file already exists in the backup directory
        if os.access(probeConfig.get_PSACCTBackupFileRepository() + PSACCTFileName, os.R_OK) == True:
            DebugPrint(0, PSACCTFileName + " already exists in backup repository!")
        else:
            # Check to see if the new file can be created
            if os.access(probeConfig.get_PSACCTBackupFileRepository(), os.W_OK) == False:
                DebugPrint(0, probeConfig.get_PSACCTBackupFileRepository() + " is not writeable!")
            else:
                # Check to see if the current file can be deleted
                if os.access(PSACCTFileName, os.W_OK) == False:
                    DebugPrint(0, PSACCTFileName + " cannot be deleted!")
                else:
                    canBackupFile = True

        DebugPrint(1, " Can backup " + PSACCTFileName + ":  ", canBackupFile)
        DebugPrint(5, "Done checking if file can be backed up")

        return canBackupFile


    #
    # BackupPSACCTFile
    #
    #  Backup PSACCT File will execute only if a pending PSACCT file is successfully processed.  When executed, this method
    #  will take the given pending file and move it to the PSACCT backup file repository (as configured in the probe config)
    #  so that it is not procesed again.
    #
    # Parameters:
    #  pendingFile - The full path to the PSACCT file that was successfully processed.
    #  probeConfig - A fully populated probe configuration object.
    #
    def BackupPSACCTFile(self,pendingFile, probeConfig):
        DebugPrint(5, "Backing up " + pendingFile)

        # Move the pending file from the PSACCT file repository to the PSACCT file backup repository
        DebugPrint(1, " Moving " + pendingFile + " to " + probeConfig.get_PSACCTBackupFileRepository() + " (PSACCT file backup repository)")
        Gratia.Mkdir(probeConfig.get_PSACCTBackupFileRepository())

        target = os.path.join(probeConfig.get_PSACCTBackupFileRepository(),os.path.basename(pendingFile))
        os.rename(pendingFile, target)

        commands.getstatusoutput("gzip -9 " + target)

        DebugPrint(5, "Done backing up " + pendingFile)

psacct = PsacctFiles()

#
# Read
#
# Read is a generic binary file reader used to prevent redundant read logic for each type
#
# Parameters:
#  PSACCTFileName - 
#  structFormat - 
# structSize -
#
# Return:
#  PSACCTRecords - A list of lists representing the records read from the file, and each entity (field value) within
#   each record..
#
def Read(PSACCTFileName, structFormat, structSize):
    DebugPrint(5, "Reading PSACCT file:  ", PSACCTFileName)

    # TODO:  Instead of parsing the binary PSACCT file, I've switched to simply running the 'dump-acct' command
    #  and interpreting its results.  Will this always work?
    #PSACCTData = []
    #PSACCTRecords = []

    #PSACCTFile = open(PSACCTFileName, "rb")
    
    #while 1:
    #    data = PSACCTFile.read(structSize)
    #    if data == "": break
    #    PSACCTData.append(data)
    
    #PSACCTFile.close()
    #PSACCTFile = None

    #for data in PSACCTData:
    #    PSACCTRecords.append(struct.unpack(structFormat, data))
 
    #allPSACCTRecords = commands.getoutput("/usr/sbin/dump-acct " + PSACCTFileName).split("\n")

    output = os.popen("/usr/sbin/dump-acct " + PSACCTFileName);

    # Remove any records that do not have a full 8 fields (split by |)
    Aggregates = {}
    RecordObjects = []
    Records = {} 
    rcount = 0
    #for record in allPSACCTRecords:
    rcount = 0
    for record in output:
        record = record.strip()
        data = record.split("|")
        if len(data) == 8:
            rcount = rcount + 1
            record = Aggregate(data)
            summary = Aggregate(data)
            # The Key arguments are the names of collections
            # First create individual records
            recordKey = record.Key("records")
            RecordObjects.append((recordKey, record))
            # Then create summaries
            summaryKey = summary.Key("summaries")
            if Aggregates.has_key(summaryKey):
                Aggregates[summaryKey].Add(summary)
            else:
                Aggregates[summaryKey] = summary
    # Create a dictionary of lists
    # dictionary - username + date + typeofrecord
    # list - record data
    for k, v in RecordObjects:
        Records.setdefault(k, []).append(v)

    output.close()

    DebugPrint(1, "Read ", rcount,  " records into ", len(Aggregates), " aggregates.")
    DebugPrint(5, "Done Reading PSACCT file:  ", PSACCTFileName)

    return Records, Aggregates



# LogException
#
# Log Exception will take a usage record that failed to be sent to the collector and save it to the exceptions
#  folder for review.
#
# Parameters
#  Usage Record - the Usage Record that failed to send to the collector
#
def LogException(usageRecord, probeConfig):
    DebugPrint(5, "Log Exception")

    # Create the exceptions directory if it doesn't exist
    if os.access(probeConfig.get_PSACCTExceptionsRepository(), os.R_OK) == False:
        Gratia.Mkdir(probeConfig.get_PSACCTExceptionsRepository())

    # Ensure the exception path can be written to
    if os.access(probeConfig.get_PSACCTExceptionsRepository(), os.W_OK):
        newExceptionFile = probeConfig.get_PSACCTExceptionsRepository() + time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
        while os.access(newExceptionFile, os.R_OK):
            newExceptionFile = probeConfig.get_ExceptionsRepository() + time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())

            newFile = open(newExceptionFile,"w")
            # TODO:  How to get the text of the usage record to write out?
            newFile.close()
            
    else:
        DebugPrint(0, "Unable to write to exception path!  ", probeConfig.get_PSACCTExceptionsRepository())

    DebugPrint(5, "Done loggine Exception")


# PsAcct
#
# Log Exception will take a usage record that failed to be sent to the collector and save it to the exceptions
#  folder for review.
#
# Parameters
#    enable - If true, PsAcct will process the 'current' process account file AND
#        enable the process accounting to 'restart' using the file psacct in the directory
#        selected in the ProbeConfig's PSACCTFileRepository entry.
#
def PsAcct(enable = True):
    probeConfig = None
    pendingFiles = []
    usageRecords = []
    failedUsageRecords = []
    try:
        modulepath = os.path.dirname(sys.argv[0])
        configfile = os.path.join(modulepath,"/etc/psacct-collector/collector.conf")
        Gratia.Initialize(configfile)
    except:
        # TODO:  Handle unexpected errors gracefully
        DebugPrint(0, "Gratia error during initialization:\n" + "Unexpected Exception" + sys.exc_info() + "--" + sys.exc_info()[0] + "++" + sys.exc_info()[1])
        sys.exit()

    try:
        if (Gratia.Config.get_ProbeName()=="Generic"):
            Gratia.Config.setProbeName(sysinfo.Hostname)

        # Load the probe configuration object
        probeConfig = Gratia.Config

        if (enable):
            psacct.MoveCurrentAccountingFile(probeConfig)
            
        # Get the PSACCT files that are pending processing
        pendingFiles = psacct.GetPSACCTFileNames(probeConfig)

        if len(pendingFiles) == 0:
            DebugPrint(0, "No pending files to process")
            Gratia.Reprocess()

        # Loop through each pending file to read and process it
        for pendingFile in pendingFiles:
            try:
                usageRecords = {}
                failedUsageRecords = {}

                # Check to see if the accounting process is running on this file
                if psacct.IsAccounting(pendingFile):
                    # Accounting is running on this file, so turn it off and restart it on a new file
                    psacct.StopAccounting(pendingFile)
                    psacct.StartNewAccounting(pendingFiles, probeConfig)

                # Read all of the records within the pending file to a dict.  Files are read differently
                # depending on their type, o each type will have its own read method
                (pendingRecords, pendingSummaries) = sysinfo.Read(pendingFile)
                # Loop through each record read from the file
                for key, pendingRecord in pendingRecords.items() :
                    for preRecord in pendingRecord :
                        usageRecords.setdefault(key, []).append(preRecord.Process());
                for key, pendingSummary in pendingSummaries.items() :
                    usageRecords.setdefault(key, []).append(pendingSummary.Process());
                # Ensure that the file can be backed up.  If it cannot, we do not want to send it to the collector
                #  and potentially end up with duplicate records the next time through (the file will still exist
                #  because it failed to backup)
                if psacct.CanBackupFile(pendingFile, probeConfig):
                    # Loop through each usage record that was loaded
                    for usageKey, usageRecord in usageRecords.items():
                        # Send the usage record to the collector
                        usageKey = usageKey.split(':')[1] # record|summary
                        responseCode = Gratia.Send(usageKey, usageRecord)
 
                        DebugPrint(1, "Response:  ", responseCode)
 
                        # If the send to Gratia failed, then append this record to the 'failed' list
                        # TODO:  Synch up with the actual response codes from Gratia.py
                        if responseCode.lower().startswith("Fatal Error"):
                            failedUsageRecords[usageKey] = usageRecord

                    # Check if ALL records failed to send
                    if len(failedUsageRecords) == len(usageRecords) and len(usageRecords) > 0:
                        # All records failed to send.  Do not backup the file or log exceptions.
                        DebugPrint(1, "All records failed to send to the collector")
                    else:
                        # At least one record successfully got to the collector.  Log the others as exceptions and
                        #  backup the psacct file so the one that made it is not processed again.
                        psacct.BackupPSACCTFile(pendingFile, probeConfig)

                        # Loop through each record that failed to send and log it into the exceptions folder
                        for failedUsageRecord in failedUsageRecords: 
                            LogException(failedUsageRecord, probeConfig)
                    
                else:
                    DebugPrint(0, "Could not backup " + pendingFile + ".  No data will be sent to the Collector")
            except:
                # TODO:  Handle unexpected errors gracefully
                Error("Unexpected Exception", sys.exc_info(), "--", sys.exc_info()[0], "++", sys.exc_info()[1])
                Error(traceback.extract_tb(sys.exc_info()[2],2))

            # Loop garbage collection
            usageRecord = None            

        # Cleanup the old files
        psacct.RemoveOldBackups(probeConfig,probeConfig.get_LogRotate())

    except:
        # TODO:  Handle unexpected errors gracefully
        Error("Unexpected Exception", sys.exc_info(), "--", sys.exc_info()[0], "++", sys.exc_info()[1])
        Error(traceback.extract_tb(sys.exc_info()[2],2))
        
    # Garbage Collection
    probeConfig = None
    pendingFiles = None
    usageRecords = None
    failedUsageRecords = None
