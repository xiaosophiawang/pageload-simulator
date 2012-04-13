#!/usr/bin/perl
#################################################################
# This crawler periodically crawls a list of pages. It saves
# both html page and har file locally.
# This crawler is a cron job which executes every hour.
#################################################################

##########################################
# Check arguments
##########################################
$argc = @ARGV;

if ($argc < 1) {
  print "Usage: " . $0 . " [# top websites to extract]\n";
  exit 0;
}

open FP, "top-1m.csv";
open FH, ">webpages_top" . $ARGV[0] . ".txt";

$num = int($ARGV[0]);
$i = 0;
while ($i < $num and $line = <FP>) {
  @arr = split(/,/, $line);
  print FH $arr[1];
  $i++;
}
close FP;
close FH;

