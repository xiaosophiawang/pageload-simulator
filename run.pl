#!/usr/bin/perl


###################################################################
# Capture pcap and har data
###################################################################

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
  die "couldnt fork\n";
}

# sub process: proc_wireshark
sub proc_wireshark {
  $tmp = `wireshark -i 3 -w pcap/output.pcap -k -a duration:10`;
}

##########################################
# Browsing web pages
##########################################
$exec_pjs = "~/Downloads/phantomjs-1.5.0/bin/phantomjs"; # TODO
$file_pjs = "phantomjs/pageload.js";
print `$exec_pjs $file_pjs`;

sleep(3);

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

###################################################################
# Analyze pcap and har data
###################################################################

