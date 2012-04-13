#!/usr/bin/perl
#################################################################
# This piece of script analyzes the difference of a web page
# over time.
# It works by hashing every line into a value. A constant hash
# value indicates that this line is not changed. Otherwise, we
# need to compare the native content.
#################################################################

use Digest::MD5 qw(md5_hex);

sub getUnmatchedLines { # Args: @hash_1, @hash_2
  my ($hash_1, $hash_2) = @_;
  @hash_1 = @{$hash_1};
  @hash_2 = @{$hash_2};
  $num_1 = @hash_1;
  $num_2 = @hash_2;
  @count = [];
  @prev1  = [];
  @prev2  = [];
  for $i (0 .. $num_1) {
    $count[$i] = [];
    $prev1[$i]  = [];
    $prev2[$i]  = [];
    $count[$i][0] = 0;
  }
  for $j (0 .. $num_2) {
    $count[0][$j] = 0;
  }

  foreach $i (1 .. $num_1) {
    foreach $j (1 .. $num_2) {
      if ($hash_1[$i] eq $hash_2[$j]) {
        $count[$i][$j] = $count[$i - 1][$j - 1] + 1;
        #$prev1[$i][$j] = $i - 1;
        #$prev2[$i][$j] = $j - 1;
      } else {
        if ($count[$i - 1][$j] > $count[$i][$j - 1]) {
          $count[$i][$j] = $count[$i - 1][$j];
        } else {
          $count[$i][$j] = $count[$i][$j - 1];
        }
      }
    }
  }
  print "# Matched lines:" . $count[$num_1][$num_2] . "\n";
}



# inputs
my $file1 = "data/crawl/1334275320/baidu.com
.html";
my $file2 = "data/crawl/1334275380/baidu.com
.html";


# read two files and compute hashes
open F1, $file1;

my $lc_1 = 0;
my @hash_1 = [];
my @cont_1 = [];
while (my $line = <F1>) {
  $line =~ s/^[ \t\n]+//g;
  if ($line) {
    $cont_1[$lc_1] = $line;
    $hash_1[$lc_1] = md5_hex($line);
    $lc_1++;
    #print $line;
    #print md5_hex($line) . "\n";
  }
}
print "# 1 lines:\t" . $lc_1 . "\n";

open F2, $file2;

my $lc_2 = 0;
my @hash_2 = [];
my @cont_2 = [];
while (my $line = <F2>) {
  $line =~ s/^[ \t\n]+//g;
  if ($line) {
    $cont_2[$lc_2] = $line;
    $hash_2[$lc_2] = md5_hex($line);
    $lc_2++;
    #print $line;
    #print md5_hex($line) . "\n";
  }
}
print "# 2 lines:\t" . $lc_2 . "\n";

getUnmatchedLines(\@hash_1, \@hash_2);
