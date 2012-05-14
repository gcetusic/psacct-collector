#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Gratia Job Usage Record Library
"""

import GratiaCore
import re
import socket
import string
import time
import xml

# For Backward compatibility
from GratiaCore import Send
from GratiaCore import SendStatus
from GratiaCore import Reprocess
from GratiaCore import ProcessBundle
from GratiaCore import DebugPrint
from GratiaCore import DebugPrintTraceback
from GratiaCore import Error

from GratiaCore import ProbeConfiguration
from GratiaCore import Record
from GratiaCore import ProbeDetails
from GratiaCore import TimeToString
from GratiaCore import Mkdir

class ConfigProxy:
    def __getattr__(self, attrname):
        return getattr(GratiaCore.Config, attrname)

class BundleProxy:
    def __getattr__(self, attrname):
        return getattr(GratiaCore.CurrentBundle, attrname)

class RecordPidProxy:
    def __str__(self):
        return str(GratiaCore.RecordPid)
      
Config = ConfigProxy()
CurrentBundle = BundleProxy()
RecordPid = RecordPidProxy()

from GratiaCore import CheckJsonDoc
from GratiaCore import RegisterReporterLibrary
from GratiaCore import RegisterReporter
from GratiaCore import RegisterService
from GratiaCore import ExtractCvsRevision
from GratiaCore import ExtractCvsRevisionFromFile
from GratiaCore import ExtractSvnRevision
from GratiaCore import ExtractSvnRevisionFromFile
from GratiaCore import Initialize
from GratiaCore import Maintenance
from GratiaCore import setProbeBatchManager
from GratiaCore import pythonVersionRequire


# Privates globals


class UsageRecord(Record):

    '''Base class for the Gratia Usage Record'''

    JobId = {}
    UserId = {}
    __Njobs = 1
    __NjobsDescription = r''
    __ResourceType = None

    def __init__(self, resourceType=None):

        # See the function ResourceType for details on the
        # parameter

        super(self.__class__, self).__init__()
        DebugPrint(1, 'Creating a UsageRecord ' + TimeToString())
        #self.JobId = {}
        self.UserId = {}
        self.Username = 'none'
        self.__ResourceType = resourceType

    def Metric(self, value):
        if len(value) > 0:
            return 'urwg:metric="' + value + '" '
        else:
            return r''

    def Unit(self, value):
        if len(value) > 0:
            return 'urwg:unit="' + value + '" '
        else:
            return r''

    def StorageUnit(self, value):
        if len(value) > 0:
            return 'urwg:storageUnit="' + value + '" '
        else:
            return r''

    def PhaseUnit(self, value):
        if type(value) == str:
            realvalue = value
        else:
            realvalue = self.Duration(value)
        if len(realvalue) > 0:
            return 'urwg:phaseUnit="' + realvalue + '" '
        else:
            return r''

    def Type(self, value):
        if len(value) > 0:
            return 'urwg:type="' + value + '" '
        else:
            return r''

    def UsageType(self, value):
        if len(value) > 0:
            return 'urwg:usageType="' + value + '" '
        else:
            return r''

    # Public Interface:

    def LocalJobId(self, value):
        self.JobId = self.AddToList(self.JobId, 'LocalJobId', r'', value)

    def GlobalJobId(self, value):
        self.JobId = self.AddToList(self.JobId, 'GlobalJobId', r'', value)

    def ProcessId(self, value):
        self.JobId = self.AddToList(self.JobId, 'ProcessId', r'', str(value))

    def GlobalUsername(self, value):
        self.UserId = self.AddToList(self.UserId, 'GlobalUsername', r'', value)

    def LocalUserId(self, value):
        self.UserId = self.AddToList(self.UserId, 'LocalUserId', r'', value)

    def UserKeyInfo(self, value):  # NB This is deprecated in favor of DN, below.
        ''' Example:
            <ds:KeyInfo xmlns:ds=http://www.w3.org/2000/09/xmldsig#>
                <ds:X509Data>
                <ds:X509SubjectName>CN=john ainsworth, L=MC, OU=Manchester, O=eScience, C=UK</ds:X509SubjectName>
                </ds:X509Data>
            </ds:KeyInfo>
        '''

        complete = '''
\t\t<ds:X509Data>
\t\t<ds:X509SubjectName>''' + value \
            + '''</ds:X509SubjectName>
\t\t</ds:X509Data>
\t'''
        self.UserId = self.VerbatimAddToList(self.UserId, 'ds:KeyInfo',
                                             'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ', complete)

    def DN(self, value):
        self.UserId = self.AddToList(self.UserId, 'DN', r'', value)

    def VOName(self, value):
        self.UserId = self.AddToList(self.UserId, 'VOName', r'', value)

    def ReportableVOName(self, value):
        ''' Set reportable VOName'''

        self.UserId = self.AddToList(self.UserId, 'ReportableVOName', r'', value)

    def JobName(self, value, description=r''):
        self.RecordData = self.AddToList(self.RecordData, 'JobName', self.Description(description), value)

    def Charge(
        self,
        value,
        unit=r'',
        formula=r'',
        description=r'',
        ):
        if len(formula) > 0:
            formulaStr = 'formula="' + formula + '" '
        else:
            formulaStr = r''
        self.RecordData = self.AddToList(self.RecordData, 'Charge', self.Description(description)
                                         + self.Unit(unit) + formulaStr, value)

    def Status(self, value, description=r''):
        self.RecordData = self.AddToList(self.RecordData, 'Status', self.Description(description), str(value))

    def WallDuration(self, value, description=r''):
        if type(value) == str:
            realvalue = value
        else:
            realvalue = self.Duration(value)
        self.RecordData = self.AddToList(self.RecordData, 'WallDuration', self.Description(description),
                                         realvalue)
        
    def CpuDuration(
        self,
        value,
        cputype,
        description=r'',
        ):
        """Register a total cpu duration.  cputype must be either 'user' or 'system'"""

        if type(value) == str:
            realvalue = value
        else:
            realvalue = self.Duration(value)
        if cputype == 'sys':
            cputype = 'system'
        if cputype != 'user' and cputype != 'system':
            description = '(type=' + cputype + ') ' + description
            cputype = r''
        self.RecordData = self.AppendToList(self.RecordData, 'CpuDuration', self.UsageType(cputype)
                                            + self.Description(description), realvalue)

    def EndTime(self, value, description=r''):
        if type(value) == str:
            realvalue = value
        else:
            realvalue = TimeToString(time.gmtime(value))
        self.RecordData = self.AddToList(self.RecordData, 'EndTime', self.Description(description), realvalue)

    def StartTime(self, value, description=r''):
        if type(value) == str:
            realvalue = value
        else:
            realvalue = TimeToString(time.gmtime(value))
        self.RecordData = self.AddToList(self.RecordData, 'StartTime', self.Description(description), realvalue)

    def TimeDuration(
        self,
        value,
        timetype,
        description=r'',
        ):
        ''' Additional measure of time duration that is relevant to the reported usage '''

        if type(value) == str:
            realvalue = value
        else:
            realvalue = self.Duration(value)
        self.AppendToList(self.RecordData, 'TimeDuration', self.Type(timetype) + self.Description(description),
                          realvalue)

    def TimeInstant(
        self,
        value,
        timetype,
        description=r'',
        ):
        ''' Additional identified discrete time that is relevant to the reported usage '''

        if type(value) == str:
            realvalue = value
        else:
            realvalue = TimeToString(time.gmtime(value))
        self.AppendToList(self.RecordData, 'TimeInstant', self.Type(timetype) + self.Description(description),
                          realvalue)

    def MachineName(self, value, description=r''):
        self.RecordData = self.AddToList(self.RecordData, 'MachineName', self.Description(description), value)

    def Host(
        self,
        value,
        primary=False,
        description=r'',
        ):
        if primary:
            pstring = 'primary="true" '
        else:
            pstring = 'primary="false" '
        pstring = pstring + self.Description(description)
        self.RecordData = self.AddToList(self.RecordData, 'Host', pstring, value)

    def SubmitHost(self, value, description=r''):
        self.RecordData = self.AddToList(self.RecordData, 'SubmitHost', self.Description(description), value)

    def Queue(self, value, description=r''):
        self.RecordData = self.AddToList(self.RecordData, 'Queue', self.Description(description), value)

    def ProjectName(self, value, description=r''):
        self.RecordData = self.AddToList(self.RecordData, 'ProjectName', self.Description(description), value)

    def Network(
        self,
        value,
        storageUnit=r'',
        phaseUnit=r'',
        metric='total',
        description=r'',
        ):
        """ Metric should be one of 'total','average','max','min' """

        self.AppendToList(self.RecordData, 'Network', self.StorageUnit(storageUnit) + self.PhaseUnit(phaseUnit)
                          + self.Metric(metric) + self.Description(description), str(value))

    def Disk(
        self,
        value,
        storageUnit=r'',
        phaseUnit=r'',
        disktype=r'',
        metric='total',
        description=r'',
        ):
        """ Metric should be one of 'total','average','max','min' """

        self.AppendToList(self.RecordData, 'Disk', self.StorageUnit(storageUnit) + self.PhaseUnit(phaseUnit)
                          + self.Type(disktype) + self.Metric(metric) + self.Description(description), str(value))

    def Memory(
        self,
        value,
        storageUnit=r'',
        phaseUnit=r'',
        memorytype=r'',
        metric='total',
        description=r'',
        ):
        """ Metric should be one of 'total','average','max','min' """

        self.AppendToList(self.RecordData, 'Memory', self.StorageUnit(storageUnit) + self.PhaseUnit(phaseUnit)
                          + self.Type(memorytype) + self.Metric(metric) + self.Description(description), str(value))

    def Swap(
        self,
        value,
        storageUnit=r'',
        phaseUnit=r'',
        swaptype=r'',
        metric='total',
        description=r'',
        ):
        """ Metric should be one of 'total','average','max','min' """

        self.AppendToList(self.RecordData, 'Swap', self.StorageUnit(storageUnit) + self.PhaseUnit(phaseUnit)
                          + self.Type(swaptype) + self.Metric(metric) + self.Description(description), str(value))

    def NodeCount(
        self,
        value,
        metric='total',
        description=r'',
        ):
        """ Metric should be one of 'total','average','max','min' """

        self.AppendToList(self.RecordData, 'NodeCount', self.Metric(metric) + self.Description(description),
                          str(value))

    def Processors(
        self,
        value,
        consumptionRate=0,
        metric='total',
        description=r'',
        ):
        """ Metric should be one of 'total','average','max','min' """

        if consumptionRate > 0:
            pstring = 'consumptionRate="' + str(consumptionRate) + '" '
        else:
            pstring = r''
        self.AppendToList(self.RecordData, 'Processors', pstring + self.Metric(metric)
                          + self.Description(description), str(value))

    def ServiceLevel(
        self,
        value,
        serviceLevelType=r'',
        description=r'',
        servicetype=r'' # Obsolete use serviceLevelType instead.
        ):
        if ( serviceLevelType == r'' ) :
           serviceLevelType = servicetype
        self.AppendToList(self.RecordData, 'ServiceLevel', self.Type(servicetype) + self.Description(description),
                          str(value))

    def Resource(self, description, value):
        self.AppendToList(self.RecordData, 'Resource', self.Description(description), str(value))

    def AdditionalInfo(self, description, value):
        self.Resource(description, value)

    # The following are not officially part of the Usage Record format

    def Njobs(self, value, description=r''):
        self.__Njobs = value
        self.__NjobsDescription = description

    def ResourceType(self, value):
        ''' Indicate the type of resource this record has been generated on.'''

        self.__ResourceType = value

    # The following usually comes from the Configuration file

    def JsonAddMembers(self):
        super(self.__class__, self).JsonAddMembers()
        self.GenericAddToList('Njobs', str(self.__Njobs), self.__NjobsDescription)
        if self.__ResourceType != None:
            self.Resource('ResourceType', self.__ResourceType)

    def VerifyUserInfo(self):
        ''' Verify user information: check for LocalUserId and add VOName and ReportableVOName if necessary'''

        id_info = {}  # Store attributes of already-present information
        interesting_keys = ['LocalUserId', 'VOName', 'ReportableVOName']
        for wanted_key in interesting_keys:  # Loop over wanted keys
            item_index = 0
            for id_item in self.UserId:  # Loop over existing entries in UserId block

            # Look for key

                match = re.search(r'<\s*(?:[^:]*:)?' + wanted_key + r'\s*>\s*(?P<Value>.*?)\s*<\s*/', id_item,
                                  re.IGNORECASE)

                # Store info

                if match:
                    id_info[wanted_key] = {'Value': match.group('Value'), 'Index': item_index}
                    break

                item_index += 1

        if not id_info.has_key('LocalUserId') or len(id_info) == len(interesting_keys):  # Nothing to do
            return

        # Obtain user->VO info from reverse gridmap file.

        vo_info = GratiaCore.VOfromUser(id_info['LocalUserId']['Value'])
        if vo_info != None:

            # If we already have one of the two, update both to remain consistent.

            for key in ('VOName', 'ReportableVOName'):
                if id_info.has_key(key):  # Replace existing value
                    self.UserId[id_info[key]['Index']] = re.sub(r'(>\s*)' + re.escape(id_info[key]['Value'])
                            + r'(\s*<)', r'\1' + vo_info[key] + r'\2', self.UserId[id_info[key]['Index']], 1)
                else:

                      # Add new

                    self.UserId = self.AddToList(self.UserId, key, r'', vo_info[key])


def LocalJobId(record, value):
    record.LocalJobId(value)


def GlobalJobId(record, value):
    record.GlobalJobId(value)


def ProcessJobId(record, value):
    record.ProcessJobId(value)
