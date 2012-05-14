#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
An example on how to create and upload Gratia record.
"""
import Gratia

def GetRecord(jobid=0):
    """ 
    Create a sample Gratia record
    """
    record = Gratia.UsageRecord('Batch')

    record.LocalUserId('cmsuser000')
    record.GlobalUsername('john ainsworth')
    record.DN('CN=john ainsworth, L=MC, OU=Manchester, O=eScience, C=UK')

    record.LocalJobId('PBS.1234.0bad')
    record.LocalJobId('PBS.1234.' + str(jobid))  # overwrite the previous entry

    record.JobName('cmsreco ', 'this is not a real job name')
    record.Charge('1240')
    record.Status('4')
    record.Status(4)

    record.Njobs(3, 'Aggregation over 10 days')

    record.Network(3.5, 'Gb', 30, 'total')

    # record.Disk(3.5, "Gb", 13891, "max")
    # record.Memory(650000, "KB", "min")
    # record.Swap(1.5, "GB", "max")

    record.ServiceLevel('BottomFeeder', 'QOS')

    record.TimeDuration(24, 'submit')
    record.TimeInstant('2005-11-02T15:48:39Z', 'submit')

    record.WallDuration(6000 * 3600 * 25 + 63 * 60 + 21.2, 
                   'Was entered in seconds')
    record.CpuDuration('PT23H12M1.75S', 'user', 'Was entered as text')
    record.CpuDuration('PT12M1.75S', 'sys', 'Was entered as text')
    record.NodeCount(3)  # default to total
    record.Processors(3, .75, 'total')
    record.StartTime(1130946550, 'Was entered in seconds')
    record.EndTime('2005-11-03T17:52:55Z', 'Was entered as text')
    record.MachineName('flxi02.fnal.gov')
    record.SubmitHost('patlx7.fnal.gov')
    record.Host('flxi02.fnal.gov', True)
    record.Queue('CepaQueue')

    record.ProjectName('cms reco')

    record.AdditionalInfo('RemoteWallTime', 94365)
    record.Resource('RemoteCpuTime', 'PT23H')

    return record


if __name__ == '__main__':
    rev = '$Revision: 3983 $'
    Gratia.RegisterReporterLibrary('samplemeterecord.py', 
                                   Gratia.ExtractSvnRevision(rev))

    Gratia.Initialize()

    rec = GetRecord()
    print Gratia.Send(rec)
