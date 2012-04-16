#!/usr/bin/perl
#################################################################
# This piece of script analyzes the difference of a web page
# over time.
# It works by hashing every line into a value. A constant hash
# value indicates that this line is not changed. Otherwise, we
# need to compare the native content.
#################################################################

use Digest::MD5 qw(md5_hex);
use Time::HiRes qw/ time sleep /;
use Switch;
use JSON;

##########################################
# Run commands based on arguments
##########################################
$argc = @ARGV;

if ($argc < 1) {
  print "Usage: " . $0 . " [html | har] [url no http or www]\n";
  exit 0;
}
$type = $ARGV[0];
$url = $ARGV[1];

# start timestamp
$start = time();

# specify timestamps
$ts_1 = "1334275320";
$ts_2 = "1334275380";

# specify file names
$file_html_1 = "data/crawl/$ts_1/$url
.html";
$file_html_2 = "data/crawl/$ts_2/$url
.html";
$file_har_1 = "data/crawl/$ts_1/$url
.har";
$file_har_2 = "data/crawl/$ts_2/$url
.har";

# main
switch ($type) {
  case ("html") {
    processHTML();
  }
  case ("har") {
    processHAR();
  }
  else {
    print "Undefined command\n";
  }
}

# end timestamp
$end = time();
print "Time spent: " . ($end - $start) . "s \n";


##########################################
# Read HTML files and calculate hash of
# each line
##########################################
sub processHTML {
  open F1, $file_html_1;
  $lc_1 = 0;
  $fs_1 = 0;
  @hash_1 = [];
  @cont_1 = [];
  while (my $line = <F1>) {
    $line =~ s/^[ \t\n]+//g;
    if ($line) {
      $cont_1[$lc_1] = $line;
      $hash_1[$lc_1] = md5_hex($line);
      $lc_1++;
      $fs_1 += length($line);
    }
  }
  print "# 1 lines:\t" . $lc_1 . "\t" . $fs_1 . "\n";

  open F2, $file_html_2;
  $lc_2 = 0;
  $fs_2 = 0;
  @hash_2 = [];
  @cont_2 = [];
  while (my $line = <F2>) {
    $line =~ s/^[ \t\n]+//g;
    if ($line) {
      $cont_2[$lc_2] = $line;
      $hash_2[$lc_2] = md5_hex($line);
      $lc_2++;
      $fs_2 += length($line);
    }
  }
  print "# 2 lines:\t" . $lc_2 . "\t" . $fs_2 . "\n";

  ($c, $b) = getUnmatchedLines(\@hash_1, \@hash_2);
  print "# Matched lines:" . $c . "\t" . $b . "\n";
  $p = $b / $fs_2;
  print "A reduction of $p in bytes\n";
}

##########################################
# Read HAR files and compare requests
##########################################
sub processHAR {
  open F1, $file_har_1;
  $hs_1 = "";
  while (my $line = <F1>) {
    $hs_1 .= $line;
  }

  open F2, $file_har_2;
  $hs_2 = "";
  while (my $line = <F2>) {
    $hs_2 .= $line;
  }

  %hs_1 = %{decode_json($hs_1)};
  %hs_2 = %{decode_json($hs_2)};

  @hs_1 = @{$hs_1{"log"}{"entries"}};
  @hs_2 = @{$hs_2{"log"}{"entries"}};

  %htable = ();
  foreach $entry (@hs_1) {
    %entry = %{$entry};
    $htable{$entry{"request"}{"url"}} = 1;
  }

  $num = 0;
  $num_new = 0;
  $counts = 0;
  @urls = [];
  foreach $entry (@hs_2) {
    $num++;
    %entry = %{$entry};
    if ($htable{$entry{"request"}{"url"}}) {
    } else {
      $url = $entry{"request"}{"url"};
      $content = `curl $url &`;
      $counts += length($content);

      # find the type of new reqs
      @arr = split(/\?/, $url);
      $urls[$num_new] = $arr[0];
      $num_new++;
    }
  }
  foreach $url (@urls) {
    print $url , "\n";
  }
  print "# new bytes: $counts \n";
  print "# new requests: $num_new/$num \n";
}

##########################################
# Align two arrays using dynamic
# programming in O(n^2)
##########################################
sub getUnmatchedLines {
  my ($hash_1, $hash_2) = @_; # Args: @hash_1, @hash_2
  @hash_1 = @{$hash_1};
  @hash_2 = @{$hash_2};
  $num_1 = @hash_1;
  $num_2 = @hash_2;
  @count = [];
  @bytes = [];
  @prev1  = [];
  @prev2  = [];
  for $i (0 .. $num_1) {
    $count[$i] = [];
    $bytes[$i] = [];
    $prev1[$i]  = [];
    $prev2[$i]  = [];
    $count[$i][0] = 0;
    $bytes[$i][0] = 0;
  }
  for $j (0 .. $num_2) {
    $count[0][$j] = 0;
    $bytes[0][$j] = 0;
  }

  foreach $i (1 .. $num_1) {
    foreach $j (1 .. $num_2) {
      if ($hash_1[$i - 1] eq $hash_2[$j - 1]) {
        $count[$i][$j] = $count[$i - 1][$j - 1] + 1;
        $bytes[$i][$j] = $bytes[$i - 1][$j - 1] + length($cont_1[$i - 1]);
        #$prev1[$i][$j] = $i - 1;
        #$prev2[$i][$j] = $j - 1;
      } else {
        if ($count[$i - 1][$j] > $count[$i][$j - 1]) {
          $count[$i][$j] = $count[$i - 1][$j];
          $bytes[$i][$j] = $bytes[$i - 1][$j];
        } else {
          $count[$i][$j] = $count[$i][$j - 1];
          $bytes[$i][$j] = $bytes[$i][$j - 1];
        }
      }
    }
  }
  return ($count[$num_1][$num_2], $bytes[$num_1][$num_2]);
}

