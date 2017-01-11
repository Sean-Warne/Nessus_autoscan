#!/usr/bin/perl
use JSON;
use LWP::UserAgent;
use Path::Class qw(file);
use strict;
use warnings;

# Variables used for scan data
my @scan_info;
my @scan_name;
my $scan;
my $scan_name;
my @scan_id;
my $scan_id;
my $hash;
my %scan;
my %hash;
my $nessus;
my ($day, $month, $year) = (localtime)[3,4,5];
$month = $month + 1;

# Variables used for curl calls
my $default;
my $token;
my $login = 0; # not logged in
my $filename = "";
my $host = ""; 
my $ua = LWP::UserAgent->new(ssl_opts => {verify_hostname => 0, SSL_verify_mode => 0x00});
my $message;
my $request;
my $response;
my $decoded;
my $post;
my $data;

# initial setup; only occurs on first run
my $setup = 1; # assume setup is complete
my $set_file = "settings.txt";
my @settings_opt;
my $dl_dir;

# read in settings file; if empty, begin setup
open (my $set_fh, '<:encoding(UTF-8)', $set_file) or die "Could not open settings.txt";

while (my $row = <$set_fh>) {
	@settings_opt = split /,/, $row;
}
close $set_fh;

$setup = $settings_opt[0];

if ($setup == 0) { # not complete, start setup

	print "Setup will now begin!\n";
	sleep(2);
	system("clear");

	print "Settings may be changed later within settings.txt\n\n";

	print "Choose the option the program will default to upon execution:\n";
	print "0 - Create scan(s) from list\n";
	print "1 - launch scan(s)\n";
	print "2 - Download completed scan(s)\n";
	print "> ";
	$default = <>;

	print "\nEnter the default directory path in which you'd like the files to download into:\n";
	print "*Note: a directory will be made for each date.\n";
	print "> ";
	$dl_dir = <>;

	# write settings to file
	$setup = 1; # complete
	chomp $setup;
	chomp $default;
	chomp $dl_dir;
	my $output = "$setup,$default,$dl_dir";
	open (my $fh_out, '>', $set_file) or die "Could not write to file";
	print $fh_out $output;
	close $fh_out;

	print "\nThank you, setup is now complete. Moving on to login...\n";
	sleep(2);
	system("clear");
}
else {
	# already complete; read in settings then continue on to login
	open (my $set_fh, '<:encoding(UTF-8)', $set_file) or die "Could not open settings.txt";

	while (my $row = <$set_fh>) {
		@settings_opt = split /,/, $row;
	}
	close $set_fh;

	$default = $settings_opt[1];
	chomp $default;
	$dl_dir  = $settings_opt[2];
	chomp $dl_dir;
}


while ($login == 0) { # attempt to login

	$nessus = $host . "session";
	my $username = "";
	my $password = "";

	# set request header
	$request = HTTP::Request->new(POST => $nessus);
	$request->header('content-type' => 'application/json');
	
	# post data to body
	$post = "{\"username\":\"$username\", \"password\":\"$password\"}";
	$request->content($post);

	# send request and receive reply
	$response = $ua->request($request);
	$message  = $response->decoded_content;

	if ($response->is_success) {
		print "Login successful! Moving onto default option...";
		sleep(2);
		system("clear");
		$login = 1;
	}
	else { # loop back through and retry
		print "HTTP POST error code: ", $response->code, "\n";
		print "HTTP POST error message: ", $response->message, "\n";
		$login = 0;
		sleep(2);
		system("clear");
	}
}

# parse response to get token
{
	my @temp = split /:/, $message, 2;
	$temp[1] = "{" . $temp[1];
	$temp[1] =~ s/{"|"}//g;
	$token = $temp[1];
}

# go to default option; 0 = create, 2 = launch, 3 = download
{ 
	if ($default == 0) { # retrieve date, get data from file, create the scans
		$nessus = $host . "scans";

		# open scans.txt to retrieve data in format
		# "policy uuid, name, description, targets\n"
		open (my $fh, '<:encoding(UTF-8)', $filename) or die "Could not open scans.txt";

		while (my $row = <$fh>) {
			@scan_info = split /,/, $row;
			my $uuid = $scan_info[0];
			my $name = $scan_info[1];
			my $desc = $scan_info[2];
			my $targ = $scan_info[3];
		
			chomp $targ;

			# create scans as I go
			$request = HTTP::Request->new(POST => $nessus);
			$request->header('X-Cookie', 'token=' . $token . '');
			$request->header('content-type', 'application/json');

			$post = "{\"uuid\":\"$uuid\",\"settings\":{\"name\":\"$name\",\"enabled\":true,\"description\":\"$desc\",\"text_targets\":\"$targ\"}}";
			$request->content($post);
			$response = $ua->request($request);
		}
		close $fh;
		$default = 1; # used to continue to next block
	}


	# open file and create a list of scan names to compare
	#  to online nessus list
	open (my $fh, '<:encoding(UTF-8)', $filename) or die "Could not open scans.txt";
	while (my $row = <$fh>) {
		@scan_info = split /,/, $row;
		my $id = $scan_info[0];
		my $name = $scan_info[1];
		push @scan_name, $name;
		push @scan_id, $id;
	}
	close $fh;


	if ($default == 1) {
		# launch 'em!
		for (my $i = 0; $i < @scan_id; $i += 1) {
			my $launch_code = $nessus . "/" . $scan_id[$i] . "/launch";
			$request = HTTP::Request->new(POST => $launch_code);
			$request->header('X-Cookie' => 'token=' . $token . '');
			$request->header('content-type' => 'application/json');
			$response = $ua->request($request);
		}
		$default = 2; # used to continue to next block
	}
	if ($default == 2) {
		# every ten seconds, check if running
		# If still running, continue loop
		# otherwise, attempt to download results as csv and nessus

		my $wait = 1;
		my $update = "Scan(s) in progress";
		$nessus = $host . "scans";
		$request = HTTP::Request->new(GET => $nessus);
		$response = $ua->request($request);
		$request->header('X-Cookie' => 'token=' . $token . '');
		$request->header('content-type' => 'application/json');

		while ($wait == 1) { # still waiting for completion..
			$wait = 0; # assume the scan is complete
		
			$response = $ua->request($request); 
			$message = $response->decoded_content;
			$data = qq<$message>;
			$decoded = JSON::XS::decode_json($data);

			# loop through JSON response and determine the status
			#  of each scan; continue until none are "running".
			foreach my $scan (${$decoded}{scans}) {
				for (my $i = 0; $i < @{$scan}; $i += 1) {
					$hash = @{$scan}[$i];
	
					my $str = %{$hash}{status};
					if ($str eq "running") {
						$wait = 1; # change flag; one is incomplete
						system("clear");
						print $update;
						sleep(10);
					}
				}
			}
			print "\n";
		}
		system("clear");
		print "Scans complete!\n";
		print "Downloading results...\n";
	
		# create file folder for this specific month/year
		#  at location specified by user
		my $path = "$dl_dir" . "$month-$year";
		my $mod_path = $path;
		mkdir $path;  

		# make separate directories for each file type
		$mod_path = $path . "/nessus";
		mkdir $mod_path;
		$mod_path = $path . "/csv";
		mkdir $mod_path;

		# download 'em!
		for (my $i = 0; $i < @scan_id; $i += 1) {
		
			$scan_name = $scan_name[$i];
				
			my $sleep_time;
			my $format;
			my $outfile;

			# Download the different file types 
			for (my $j = 0; $j < 2; $j += 1) {
				$mod_path = $path;
				
				my $dl_code = $nessus . "/" . $scan_id[$i] . "/export";
				$request = HTTP::Request->new(POST => $dl_code);
				$request->header('X-Cookie' => 'token=' . $token . '');
				$request->header('content-type' => 'application/json');
			
				# used to download one file of each type
				if ($j == 0) {
					$format = "nessus";
					$sleep_time = 10;
					$mod_path = $mod_path . "/nessus";
				}
				else {
					$format = "csv";
					$sleep_time = 5;
					$mod_path = $mod_path . "/csv";
				}

				# export scan results to get result id
				#  used in downloading
				$outfile = "$scan_name.$format";
				if (index($outfile, "/") != -1) {
					$outfile =~ s/\///g;
				}
				$post = '{"format":"' . $format . '"}';
				$request->content($post);
				$response = $ua->request($request);

				# sleep so report can be fully generated before download
				sleep($sleep_time);

				$message = $response->decoded_content;
				$data = qq<$message>;
				$decoded = JSON::XS::decode_json($data);
				$message = ${$decoded}{file};	

				# download exported results of scan
				$dl_code = $nessus . "/" . $scan_id[$i] . "/export/" . $message . "/download?token=" . $token;
				$request = HTTP::Request->new(GET =>$dl_code);
				$response = $ua->request($request);
				$message = $response->decoded_content;

				# set file download location by modifying $outfile 
				#  with specified directory
				chomp $outfile;
				my $to_write = "$mod_path/$outfile";

				if (length($to_write) >= 256) { # filename is too long
					chomp $to_write;
					$to_write =~ s/" "//g;
				}

				# write scan output ($message) to file
				open(my $fh, '>', $to_write) or die "Could not open file";
				print $fh $message;
				close $fh;
			}	
		}
	}
}
