#!/usr/bin/perl

##########################################
# Check arguments
##########################################
$argc = @ARGV;

if ($argc < 1) {
  print "Usage: " . $0 . " [url no http]\n";
  exit 0;
}
$url = $ARGV[0];
print $url;

##########################################
# Configure and start wireshark
##########################################
print "Start wireshark\n";

$pid = fork();
if ($pid) {
} elsif ($pid == 0) {
  proc_wireshark();
  exit 0;
} else {
  die "couldn't fork\n";
}

# sub process: proc_wireshark
sub proc_wireshark {
  $tmp = `wireshark -i 3 -w data/pcap/$url.pcap -k -a duration:10`;
}

##########################################
# Browsing web pages
##########################################
# We have two options here
# 1. phantomJs which is not a real browser, but has nice APIs to access
# 2. selenium which can drive a real browser, but we should hook on extensions
$exec_pjs = "~/Downloads/phantomjs-1.5.0/bin/phantomjs"; # TODO
$file_pjs = "phantomjs/pageload.js";
$file_har = `$exec_pjs $file_pjs http://$url`;
# write har file to local disk
open FH, ">data/har/$url.har";
print FH $file_har;
close FH;

##########################################
# End Wireshark by killing procs
##########################################
print "End of wireshark\n";

$tmp = `ps`;
@aPS = split(/\n/, $tmp);
foreach $PS (@aPS) {
  if ($PS =~ /Wireshark/) {
    @items = split(/\s/, $PS);
    $ps_id = int($items[0]);
    print `kill $ps_id`;
  }
}
# kill the forked process as well
kill $pid;

