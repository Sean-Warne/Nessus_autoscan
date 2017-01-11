Nessus Scanner Automated Downloader
Author: Warne, Sean
Date: October 3, 2016


Objective: 
To automatically create, run, and/or download the results of a Nessus network scan.


Instructions:
1. Run ./getscannames.pl or /path/to/getscanlnames.pl to create a list of nessus scans
2. Modify scans.txt to add/remove any scans you don't want to be run
3. Run ./nessus.pl (local) or /path/to/nessus.pl to begin the auto process
4. Setup will begin on inital run only; follow prompts to complete
	a. The path to the output must be entered here so have ready
5. Program will execute (this may take a while, depending on # of scans)
6. Results will be available in output folder under /<month-year>/csv or /nessus

Note 1: The settings file contains any relevant settings in the format:
	<setup complete | 0/1>,<default option to execute | 1-3>,<file location | string>

Note 2: The settings file may be configured using a text editor at any time


Other information:
> It uses the scans.txt file to determine which scans to download. If a scan is added on
  the server, the user must add a line in scans.txt using the format of previous entries
  such that the new results will be downloaded. The id of the scan can be found in the
  URL of that scan on the Nessus web server. 
> Three Perl dependencies must be installed for this program to run:
	o JSON
	o LWP::UserAgent
	o Path::Class
