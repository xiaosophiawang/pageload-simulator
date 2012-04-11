#!/usr/bin/perl

##########################################
# Check arguments
##########################################
$argc = @ARGV;

if ($argc < 1) {
  print "Usage: " . $0 . " [NUM of parallel connections] [file names]\n";
  exit 0;
}

$num_connections = int($ARGV[0]);
$filename = $ARGV[1];
$path = "../../data/pages/";
$file_fullpath = $path . $filename . "/files/";
$prefix = "main";

# work as is if there is only one connection
if ($num_connections == 1) {
  print `sh image2css.sh -f $file_fullpath -o $path$filename/$prefix.css -h $path$filename/$prefix.html`;
  exit(0);
}

# consider the case of multiple connections
print `rm -rf $path$filename/files_*`;
print `rm -rf $path$filename/$prefix*`;
$files = `ls $file_fullpath`;
@files = split(/\n/, $files);
$total_size = 0;
foreach $file (@files) {
  # only consider image files
  @parts = split(/\./, $file);
  $suffix = $parts[$parts - 1];
  if ($suffix eq "jpg" or $suffix eq "gif" or $suffix eq "png" or $suffix eq "bmp") {
    $file_name = $file_fullpath . $file;
    $file_size = -s $file_name;
    #print $file_name . "\t" . $file_size . "\n";
    $total_size += $file_size;
  }
}
print "Bytes of all images: " . $total_size . "\n";
$avg_size = $total_size / $num_connections;

$body = "<body>\n";
$head = "<head>\n";
$cum_size = 0;
$files_i = 1;

# create the first folder
$dir_name = $path . $filename. "/files_" . $files_i;
$head .= "\t<link rel='stylesheet' type='text/css' href='$prefix$files_i.css' />";
print `mkdir $dir_name`;
foreach $file(@files) {
  # only consider image files
  @parts = split(/\./, $file);
  $suffix = $parts[$parts - 1];
  if ($suffix eq "jpg" or $suffix eq "gif" or $suffix eq "png" or $suffix eq "bmp") {
    $file_name = $file_fullpath . $file;
    $file_size = -s $file_name;

    $cum_size += $file_size;
    if ($cum_size > $avg_size) {
      # generate css and html
      print $dirname . "\n";
      print `sh image2css.sh -f $dir_name -o $path$filename/$prefix$files_i.css`;

      # prepare a new folder
      $files_i += 1;
      $dir_name = $path . $filename . "/files_" . $files_i;
      $head .= "\t<link rel='stylesheet' type='text/css' href='$prefix$files_i.css' />";
      print `mkdir $dir_name`;

      # clear cummulative file size
      $cum_size = 0;
    } else {
      print `cp -rf $file_name $dir_name`;
    }

    # add to html
    $file_name_c = $file;
    $file_name_c =~ s/\./_/g;
    $body .= "\t<div class='$file_name_c'></div><br />$file_name_c<br /><hr />\n";
  }
}
$body .= "</body>\n";
$head .= "</head>\n";
print $dirname . "\n";
print `sh image2css.sh -f $dir_name -o $path$filename/$prefix$files_i.css`;

open FP, ">$path$filename/$prefix.html";
print FP "<html>\n";
print FP $head;
print FP $body;
print FP "</html>";
close FP;
