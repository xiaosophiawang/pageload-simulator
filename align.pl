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

##########################################
# Check arguments
##########################################
$argc = @ARGV;

if ($argc < 1) {
  print "Usage: " . $0 . " [url no http or www]\n";
  exit 0;
}
$url = $ARGV[0];

# inputs
my $file1 = "data/crawl/1334275320/$url
.html";
my $file2 = "data/crawl/1334275380/$url
.html";

$start = time();

# read two files and compute hashes
open F1, $file1;

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

open F2, $file2;

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

$end = time();

print "Time spent: " . ($end - $start) . "s \n";


sub getUnmatchedLines { # Args: @hash_1, @hash_2
  my ($hash_1, $hash_2) = @_;
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

