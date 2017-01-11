# Author: Warne, Sean

# used to get the scan information of current scans
#  FUTURE: modify to only get recent scans or list of desired scans
#  instead of all of them.
#!/usr/bin/perl
use JSON;
use LWP::UserAgent;
use strict;
use warnings;

my $file = "";
my $token;
my $host = "";
my $ua = LWP::UserAgent->new(ssl_opts => {verify_hostname => 0, SSL_verify_mode => 0x00});
my $message;
my $request;
my $response;
my $decoded;
my $post;
my $data;
my $hash;
my $nessus;

my @names;
my @ids;

# login #
#########
my $username = "";
chomp $username;
my $password = "";
chomp $password;

# set request header
$nessus = $host . "session";
$request = HTTP::Request->new(POST => $nessus);
$request->header('content-type' => 'application/json');

# post data to body
$post = "{\"username\":\"$username\",\"password\":\"$password\"}";
print "\n$post\n";
$request->content($post);

# send request and receive response
$response = $ua->request($request);
$message = $response->decoded_content;

sleep(5);

# parse response to get token
my @temp = split /:/, $message, 2;
$temp[1] = "{" . $temp[1];
$temp[1] =~ s/{"|"}//g;
$token = $temp[1];

# get scan names #
##################
$nessus = $host . "scans";
$request = HTTP::Request->new(GET => $nessus);
$request->header('X-Cookie' => 'token=' . $token . '');
$request->header('content-type' => 'application/json');
$response = $ua->request($request);
$message = $response->decoded_content;

# convert from string to json
$data = qq<$message>;
$decoded = JSON::XS::decode_json($data);

sleep(2);

# get all names and add them to the array
my $id = 0;
foreach my $scan (${$decoded}{scans}) {
	for (my $i = 0; $i < @{$scan}; $i += 1) {
		$hash = @{$scan}[$i];
		my $folder = %{$hash}{folder_id};
		my $flag;

		# only add if in folder 2 (current scans)
		if ($folder == 2) {
			my $name = %{$hash}{name};
			$id = %{$hash}{id};
			$flag = 0; # assume it's not in the array
		
			# avoid duplicates	
			for (my $j = 0; $j < @ids; $j += 1) {
				if ($id == $ids[$j]) {
					$flag = 1; # already in array
					last;
				}
			}
			if ($flag == 0) { # not in the array
				push @names, $name;
				print "\n$id\t";
				push @ids, $id;
			}
		}
	}
}

# open file and add list of names to scans.txt
open (my $fh, '>', $file) or die "Could not open scans.txt";
for (my $i = 0; $i < @ids; $i += 1) {
	my $temp = "$ids[$i],$names[$i],*,*\n";
	print $fh $temp;
}
close $fh;
