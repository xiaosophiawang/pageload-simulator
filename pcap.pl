#!/usr/bin/perl

##########################################
# Check arguments
##########################################
$argc = @ARGV;
$ip = "172.28.7.27";
$ip_ap = "172.28.7.1";

# compile pcap analyzer
print `rm pcap/pcap_analyzer`;
print `gcc -o pcap/pcap_analyzer -lpcap pcap/pcap_analyzer.c`;

# run files
# TODO auto find filenames and ip addrs
$filename = "cnn.com_1334002655";
$result = `./pcap/pcap_analyzer -t data/pcap/$filename.pcap -i $ip`;

# write data file to local disk
open FH, ">data/results/$filename";
print FH $result;
close FH;

# construct hashes
%hash = ();

@frames = split(/\n/, $result);
foreach $frame (@frames) {
  @items = split(/\t/, $frame);
  $num = @items;
  if ($num > 1 and $items[2] != $ip_ap) {
    $key = $items[2] . " " . $items[3];
    if ( exists $hash{$key}) {
    } else {
      $hash{$key} = [];
    }
    push (@{$hash{$key}}, $items[0] . "\t" . $items[4] . "\t" . $items[5]);
  }
}

# find out # of parallel requests
@timestamps = []; # last timestamp of all currently open connections
$para_conn = 0;
$count = 0;
foreach $key (keys %hash) {
  $count += 1;
  @arr = @{$hash{$key}};
  $num = @arr;
  @sitems = split(/\t/, $arr[0]);
  @eitems = split(/\t/, $arr[$num - 1]);

  # calculate max # of parallel connections by maintaining the @timestamps array
  # note that we could do it using heap in O(logn). For simplicity, we do it in O(n)
  @temp_timestamps = [];
  $temp_i = 0;
  foreach $ts (@timestamps) {
    if (int($ts) > int($sitems[0])) {
      $temp_timestamps[$temp_i] = int($ts);
      $temp_i += 1;
    }
  }
  $temp_timestamps[$temp_i] = int($eitems[0]);
  @timestamps = @temp_timestamps;
  $num_ts = @temp_timestamps;
  if ($num_ts > $para_conn) {
    $para_conn = $num_ts;
  }
}
print "Max # of parallel connections: " . $para_conn . "\n";
