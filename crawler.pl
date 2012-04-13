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
  print "Usage: " . $0 . " [file name of the list of domains]\n";
  exit 0;
}

# create a new folder in which we store the new data
$path = "/Users/wangxiao/research/website/pageload-simulator";
$timestamp = time();
print `mkdir $path/data/crawl/$timestamp`;

# Read domains from the file
open FP, $ARGV[0];

while (my $domain = <FP>) {
  $exec_pjs = "/Users/wangxiao/Downloads/phantomjs-1.5.0/bin/phantomjs"; # TODO
  $file_pjs = "$path/phantomjs/pageload.js";
  $url = "http://www." . $domain;

  # get har file
  $file_har = `$exec_pjs $file_pjs $url`;
  open FH, ">$path/data/crawl/$timestamp/$domain.har";
  print FH $file_har;
  close FH;

  # get html file
  $html = `curl $url`;
  open FH, ">$path/data/crawl/$timestamp/$domain.html";
  print FH $html;
  close FH;
}
close FP;
