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
$filename = "piigeon.org_datauri_tudou.html_1334081534";
$filename = "abstract.cs.washington.edu_-wangxiao_datauri_tudou.html_1334081292";
$filename = "abstract.cs.washington.edu_-wangxiao_datauri_run.php_1334083375";
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
    $opt = ($num > 6) ? $items[6] : '';
    push (@{$hash{$key}}, $items[0] . "\t" . $items[1] . "\t" . $items[4] . "\t" . $items[5] . "\t" . $items[6]);
  }
}

# find out # of parallel requests
# find window sizes
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

  # calculate window sizes
  print "\n" . $key;
  $ch = 0;
  $rtt = 0;
  $last_ts = 0;
  $win_size = 0;
  foreach $frame (@arr) {
    @items = split(/\t/, $frame);
    # $items[0] - timestamp
    # $items[1] - direction
    # $items[2] - tcp payload size
    # $items[3] - flags
    # $items[4] - 443 or http get if any

    # a new req
    $opt = ($items[4] && int($items[2]) < 1368) ? "GET" : '';
    if ($opt) {
      print $win_size;
      print "\n" . $opt . "\t";
      $win_size = 0;
      $last_ts = int($items[0]);
    }
    if ($items[1] eq "out" and int($items[2]) > 0) { # HTTP GET
      $ch = 1;
      $win_size = 0;
      $last_ts = 0;
    }
    if ($items[1] eq "out" and $items[3] eq "ACK FIN ") { # client sends FIN
      $ch = 0;
    }
    if ($ch == 1 && $items[1] eq "in" && int($items[2]) > 0) {
      #print $items[1] . "\t" . $items[2] . "\t" . (int($items[0]) - $last_ts) . "\n";
      if ($last_ts > 0 && int($items[0]) - $last_ts > $rtt * 0.4) {
        if ($win_size > 0) {
          print $win_size . "\t";
        }
        $win_size = 0;
        $last_ts = 0;
      }
      $win_size += 1;
      $last_ts = int($items[0]);
      
    } elsif ($ch == 0) { # work out RTT from three-way handshake
      if ($items[3] eq "SYN ") {
        $last_ts = int($items[0]);
      } elsif ($items[3] eq "ACK SYN ") {
        $rtt = int($items[0]) - $last_ts;
        print "\nRTT: " . $rtt . "\n";
      }
    }
  }
  if ($win_size > 0) {
    print $win_size . "\n";
  }
  print "\n";
}
print "Max # of parallel connections: " . $para_conn . "\n";
