#!/usr/bin/perl

##########################################
# Check arguments
##########################################
$argc = @ARGV;

# compile pcap analyzer
print `rm pcap/pcap_analyzer`;
print `gcc -o pcap/pcap_analyzer -lpcap pcap/pcap_analyzer.c`;

# run files
$filename = "cnn.com_1334002655";
$result = `./pcap/pcap_analyzer -t data/pcap/$filename.pcap -i 172.28.7.27`;

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
  if ($num > 1 and $items[2] != "172.28.7.1") {
    $key = $items[2] . " " . $items[3];
    print $key . "\n";
    if ( exists $hash{$key}) {
    } else {
      $hash{$key} = [];
    }
    push (@{$hash{$key}}, $items[0] . "\t" . $items[4] . "\t" . $items[5]);
  }
}

# find out # of parallel requests

@websites = [];
foreach $key (keys %hash) {
  @arr = @{$hash{$key}};
  $num = @arr;
  print $key . " " . $arr[0] . "\n";
}
