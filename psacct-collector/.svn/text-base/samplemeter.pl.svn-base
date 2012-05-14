#!/usr/bin/env perl

use FileHandle;

$py = new FileHandle;
$py->open("| python");
print $py "import Gratia\n";
print $py "Gratia.Initialize()\n";
print $py "r = Gratia.UsageRecord()\n";
print $py "r.DN(\"CN=john ainsworth, L=MC, OU=Manchester, O=eScience, C=UK\")\n";

print $py "r.LocalJobId(\"PBS.1234.0bad\")\n";
print $py "r.LocalJobId(\"PBS.1234.0\") # overwrite the previous entry\n";
print $py "r.LocalUserId(\"cmsuser000\")\n";
print $py "r.JobName(\"cmsreco\",\"this is not a real job name\")\n";

print $py "r.WallDuration(3600*25+63*60+21.2,\"Was entered in seconds\")\n";
print $py "r.CpuDuration(\"PT23H12M1.75S\",\"user\",\"Was entered as text\")\n";
print $py "r.StartTime(1130946550,\"Was entered in seconds\")\n";
print $py "r.EndTime(\"2005-11-03T17:52:55Z\",\"Was entered as text\")\n";
print $py "r.TimeDuration(24,\"submit\")\n";
print $py "r.TimeInstant(\"2005-11-02T15:48:39Z\",\"submit\")\n";

print $py "r.MachineName(\"flxi02.fnal.gov\")\n";
print $py "r.Host(\"flxi02.fnal.gov\",True)\n";
print $py "r.SubmitHost(\"patlx7.fnal.gov\")\n";
print $py "r.Queue(\"CepaQueue\")\n";
print $py "r.ProjectName(\"cms reco\")\n";

print $py "r.Network(3.5,\"Gb\",30,\"total\")\n";
#print $py "r.Disk(3.5,\"Gb\",13891,\"max\")\n";
#print $py "r.Memory(650000,\"KB\",\"min\")\n";
#print $py "r.Swap(1.5,\"GB\",\"max\")\n";
print $py "r.NodeCount(3) # default to total\n";
print $py "r.Processors(3,.75,\"total\")\n";
print $py "r.ServiceLevel(\"BottomFeeder\",\"QOS\")\n";
print $py "r.Charge(\"1240\")\n";

print $py "r.AdditionalInfo(\"RemoteWallTime\",94365)\n";
print $py "r.Resource(\"RemoteCpuTime\",\"PT23H\")\n";
print $py "#\n";
print $py "# populate r\n";
print $py "Gratia.Send(r)\n";

$py->close;
