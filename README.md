# uberscan
Security program for pen-testing servers, routers and IoT devices


  Greeetings, comrades, and welcome to UBERSCAN 1.0

UBERSCAN is designed to help pen-test servers and networks, and as a tool for people like me who are trying to get into the ethical hacking business to just get a handle on, for example, just how many devices are vulnerable to, say, the Mirai virus. Yes, it's a sort of wardialler and yes, it can be used to crack the passwords of servers and IoT devices, and no, it is not to be used for sinister or nefarious purposes (see LEGAL NOTICE).

## Quick Start:
Example command-line usage:

`uberscan -user:admin -passblank -scantype:telnet -random_ip -forktimes:20`

or

`uberscan -user:root -password:admin -scantype:ssh -random_ip -forktimes:20`

or maybe

`uberscan -userfile:wordlist.txt -passfile:wordlist.txt -scantype:telnet -random_ip -forktimes:15`

Try combining and adjusting these various options until you find some fun things to play with!

-------------------------------------------------------------------------------------------

## CONTENTS:

#### 0.... LEGAL NOTICE

#### 1.... INSTALLATION

#### 2.....ABSTRACT
##### 2.1...Introduction
##### 2.2...A note on wordlist mode
##### 2.3...The SSH scanner
##### 2.4...Easter eggs
##### 2.5...Signoff and whiny begging bit

#### 3.....OPTIONS


---------------------------------------------------------------------------------------

0. LEGAL NOTICE:

This program (herafter referred to as UBERSCAN or uberscan) is distributed under the GPL 3 license. All relevant rights reserved. UBERSCAN IS COPYRIGHT (c) Batch McNulty 2017. You may distribute, modify and / or copy UBERSCAN without permission as long as you abide by the terms of the GPL 3 license.

This utility is designed for LEGAL USE ONLY. I will not be held responsible for malicious use.
Malicious hackers are going to have their own tools anyway; UBERSCAN is designed to help secure computer systems, not trash them. If you do find vulnerable servers using the -random_ip and -random_ipblock scanners you are encouraged to contact the owners and tell them about the security hole. 

Be nice! That's an order!

Please send all death threats, extradition warrants, and dodgy job offers to batchmcnulty@protonmail.com. I will try to get back to you but can't guarantee anything...

---------------------------------------------------------------------------------------



1. INSTALLATION:

It has a few dependencies, so I'm shipping a batch file with it that should install those for you automatically. Just open a terminal window in whatever directory it's in and type

sudo bash INSTALL.bash

..wait (it can take a long time), and you should be able to run UBERSCAN (try perl uberscan.pl if you get really stuck)


In case the install program doesn't work, the required libraries are:

WWW::Curl::Easy
HTTP::Request
Net::SSH::Expect
Net::Telnet
Net::FTP
Net::POP3
IO::Socket::INET
Scalar::Util
Fcntl
utf8
Encode

Scalar::Util, Fcntl, utf8 and Encode should all be included in your Perl distro, which comes with Linux. The others probably need to be installed seperately... sadly in the case of Curl::Easy the dependency itsself has a dependancy, which can be hard to find. If the INSTALL.bash file doesn't leave you with a computer that runs UBERSCAN, try running one or all of these, then run the install file again:

    sudo apt-get install libcurl4-doc 
    sudo apt-get install libcurl3-dbg 
    sudo apt-get install libgnutls-dev
    sudo apt-get install libidn11-dev
    sudo apt-get install libkrb5-dev 
    sudo apt-get install libldap2-dev
    sudo apt-get install librtmp-dev
    sudo apt-get install zlib1g-dev


Also, the INSTALL.bash file requires cpan, which should come with linux - if it doesn't, type 

    sudo apt-get install cpan

at the terminal before running it.

 One more very important thing:

The Net::SSH::Expect module requires that you make some changes to one of your system files. It is:

/etc/ssh/ssh_config

You'll need superuser permissions to adjust that, so load it up in your favourite editor and add the following lines to it:

Host * 

    StrictHostKeyChecking no
    UserKnownHostsFile=/dev/null

(The "Host *" line may already exist, if it does, don't add a new one)

If you can't do this, uberscan will still work - you just won't be able to use the -scantype:ssh option.


----------------------------------------------------------------------------------------

2. ABSTRACT: 

2.1 Introduction

UBERSCAN was designed on an Ubuntu Linux platform, so I can't guarantee that it will run on anything else, though I'm fairly confident it will be OK on any Linux PC. Windows and Macs, not so much, but feel free to help yourselves.

UBERSCAN can scan a TCP/IP network for poorly passworded devices (including routers and IoT boxes) and SMTP mail servers vulnerable to spammers. Its main function is to brute-force password-protected servers (for ethical purposes ONLY, of course!)


It can scan for the following services / vulnerabilities:

* SSH (Secure Shell) with poor password protection
* Telnet (open on many routers and Internet Of Things devices)
* FTP (open on many routers)
* Anonymous FTP servers.
* unencrypted POP3 mail servers
* SMTP mail servers - the classic "SMTP bug", SMTP VRFY commands, and SMTP servers that can be hijacked by spammers (NB, it does NOT do password cracking on SMTP servers... yet).
* devices protected by HTTP "challenge" (NOT "forms") - both "Realm" and "Digest" type. 
* As a bonus it can also scans for "banners", the first line sent by a device, so you can look for, say banners on the mysql port.

UBERSCAN is programmed with the default ports, but you can override this with the -port: option.



2.2 A note on wordlist mode:

Wordlist mode (-passlist:textfile.txt and -userlist:textfile:txt) pages through wordlists and tries to brute-force the selected IPs with them. 

Wordlist mode differs in different scans. When you select an IP block, IP range or list of IPs, UBERSCAN goes through the targets and tries the same username / password on each IP, then loops back and tries the next username and / or password in the list until it runs out of wordlist(s). This is a rather basic attempt to overcome the old "three-strikes and you're out" style password security - if the list is long enough, by the time the same IP loops back again you'll have a fresh "go" at it.

Random IP generation (-random_ip) mode works differently. Because IPs are chosen randomly and the search can go on indefinitely, there is no list of IPs to loop through, so the entire wordlist has to be dropped on the target at once.



2.3 The SSH scanner:

Programming the SSH scanner has given me a lot of trouble. I have programmed it to look for the "~", ">", and "#" prompts as well as a "Welcome to" message, a large number of "bad password" type outputs and also created a third option, which is that if it finds neither it creates an "SSH-MAYBES.txt" file. It shouldn't create false negatives or false positives, but if it does, please send me any files it generates (suitably edited of course) so I can fix the problem.



2.4 Easter eggs:

There are a couple of fun cultural references in one or two of the program's status and error messages. These give UBERSCAN a bit of personality. If this creates confusion or seems a bit too silly I'm always happy to recieve feedback.



2.5 Signoff and whiny begging bit:

Admittedly, UBERSCAN is a bit crude, but it doesn't have to stay that way. I'm putting a bitcoin address with this, and if I get a good enough response, I'll work on refining its crudeness and there will be UBERSCAN 1.1, 1.2, maybe even an UBERSCAN 2.0. It all depends on you! Send your money to bitcoin address:

1PEDKUiUTxGNJ3XTPfXCTAjpzVzX1VZAme

-Remember, if you use this program as part of your job, you really should pay! (As an added inducement- if I get enough cash, and people ask me to, I might even take the nag screen out!)


----------------------------------------------------------------------------------------


3. OPTIONS / USAGE:


Although it will work without them, it is strongly reccomended that you give UBERSCAN superuser privileges. 

UBERSCAN is a command-line utility, and as such it expects to have at least one option passed to it.


Those Options In Full:


TYPES OF SCAN:


-scantype:xxx
Sets the scan type. "xxx" can be  SSH, FTP, POP3, SMTP, HTTP, Telnet, or Banner. See -ftpanon and -smtpbug


-port:nn
Sets the port to something other than the default for that service. ("-scantype:banner" searches on Port 1433, the SQL port).


-ftpanon
Searh for anonymous ftp servers. Used instead of -scantype and -user -pass


-smtpbug
Tests for the smtp bug. Used instead of -scantype and -user -pass options


-spamcheck
Only works under "-scantype:smtp" scans. Each and every time a server is connected to, it checks to see if it's vulnerable to abuse by spammers. Off by default.


-novrfy
When doing an SMTP scan, stops UBERSCAN from issuing VRFY commands. Implies -spamcheck.



USERNAME AND PASSWORD SCANNING:


-user:xxx
-pass:xxx
Sets the username / password to try. If you're cruising the internet for random servers with the -random_ip option, this and -userblank / -passblank are the only username / password options that UBERSCAN will accept. Normally you will use both, but they are interchangable with the -userfile and -passfile (wordlist) options where these are allowed, as well as the -userblank and -passblank options. Please note that these don't do anything if -scantype is set to SMTP or if the -ftpanon or -smtpbug options have been set.



-userblank
-passblank
-userblank sets it up to try a blank username, -passblank sets a blank password. This may come in handy for some HTTP challenges where one or both of these are left blank by default.



-userfile:wordlist.txt
-passfile:wordlist.txt
Tries each name and password in the specified wordlist. I can only guarantee them to work with regular space-seperated words- the use of wordlists containing accents, non-Latin characters, and symbols is at your own risk (though the "@" symbol should work OK).



LOGGING, RETRIES, TIMEOUTS, PORT SCANNING and PAUSE:


-debug 
Logs failed login attempts as well as all but the most commonplace errors. Errors logged in debug mode are sudden disconnects while connected to servers, along with the failed login attempts this can also be used to diagnose unexpected replies. Also saves webpages gathered in -scantype:html mode


-logall 
As -debug, but also logs very commonplace errors that would otherwise drown out the more interesting ones (these are marked as "Banal error"). Implies -debug (IE, you don't have to enter the "-debug" option if you use "-logall").


-csv
ALL output files, with the exception of webpages saved in html scanning mode, are saved in CSV format.
Data saved, in order saved is: Process ID, scan type, IP address, port number, username, password, and "minutesup" - the number of minutes UBERSCAN has been running.


-whois
Performs a WHOIS query on the server when a password is found and logs the result in a text file (whoisreport.txt). Off by default.


-max_retries:nn
This is set to 5 by default. If you're one of those poor paranoid sods working away behind their proxies and shoddy wi-fi connections, feel free to crank it up to 15 or 20 - I know I did! A normal person might even want to adjust it downwards, on the other hand if you really want to make sure you try every password on every single IP you could set it ridiculously high, like to -max_retries:999 (though I don't reccomend that!)


-timeout:nn
where nn is a number. Sets the timeout variable in seconds. Defaults to 60. If you're behind a proxy, you'll want it to be quite high, in the hundreds (I wrote this program behind a proxy). If you're using the SSH scan a lot, you might want it lower due to the way SSH::Expect works - it won't return data until the timeout period has passed. If you're just using it on your LAN and never connecting to the internet, maybe even lower. Personally I wouldn't have it lower than 60 seconds.


-portscan_timeout:
Again, this is a number of seconds. It's set low, but on occaision if you want to be completely sure you might want to yank that up to 5 or even 10. It's your choice.


-noportscan
Turns off port scanning. This feature's useful if you're behind proxychains or a proxychains-like proxying program or if you are pretty sure you've got a valid IP address / port to hack, and don't want to risk skipping it by mistake. Especially when you're behind a poor connection.


-pause
Pauses UBERSCAN after processing inputs so you can check you've set it up correctly. Off by default.



MULTITASKING:


-forktimes:nn
Uses parallel processing to make multiple connections at the same time - Please note that the -forktimes option only works if the -random_ip or -random_ipblock option is set. I personally choose a value between 5 and 15, though your mileage may vary depending on how much bandwidth you have available. It has been known to crash in this mode - so as an alternative you might find it easier to simply set up a batch file with a lot of commands like this copied and pasted into it:

perl uberscan.pl -user:admin -pass:password -random_ip -scantype:telnet &

and then run it with bash.


IP OPTIONS:

By default, UBERSCAN seeks ip addresses from a file called ipnumbers.txt. If this is inconvenient, there are a lot of command-line options that allow you to select IPs from your own file, randomly select them, or (crudely) generate them from IP ranges or IP blocks. You can even select an individual IP address and scan that - very good for intense dictionary attacks!


-ipfile:filename.txt
Get ip addresses from file filename.txt. This can be any file. It searches the given file for anything fitting an IP address and puts it in a list which it then scans. This means that it should be able to parse its own output, so you can run a -random_ip scan with the -debug or -logall options on, rename the errors.txt file it outputs and feed that into a new scan without doing all that annoying editing.


-ipblock:nnn.nnn.0.0/16
-ipblock:nnn.nnn.nnn.0/24
-ipblock:192.168.0/16	- Search everything from 192.168.0.0 - 192.168.255.255
-ipblock:192.168.1/24	- Search everything from 192.168.1.0 - 192.168.1.255
Scan selected ipblock (/16 or /24) instead of using ipnumbers.txt. 
It isn't very clever - it only counts from zero, so if you enter 192.168.1.0/16 it will still search from 192.168.0.0 to 192.168.255.255. Don't worry though, there's always -iprange!


-iprange:nnn.nnn.nnn.nnn - nnn.nnn.nnn.nnn
-iprange:192.168.0.0 - 192.168.0.3 
-iprange:192.168.5.0 - 192.168.7.2 
Scans specified range of ip numbers. It can only process the last two octets though.


-ipsingle:nnn.nnn.nnn.nnn
-ipsingle:192.168.0.1 
Scans a single ip - very powerful if used in conjunction with the -userfile: and -passfile: options!


-random_ip
Loops though a routine that creates random ip numbers so you can cruise the wild internets looking for some hot action. DO NOT USE THIS FOR NEFARIOUS PURPOSES!


-random_ipblock:nnn
-random_ipblock:nnn.nnn
As -random_ip, but only searches in the specified IP block. Note that trailing zeroes and slash notation are NOT USED IN THIS OPTION! (unlike the -ipblock option) Example:

perl uberscan.pl -scantype:banner -random_ipblock:192.168
perl uberscan.pl -scantype:banner -random_ipblock:192


LEGALESE / BOILERPLATE:

The exciting world of legal boilerplate is now available to you, simply invoke UBERSCAN with the -gpl option to see the licence it's distributed under scroll past your face. Seriously, anyone thinking of editing and / or redistributing this program should read it - you're allowed to do so, but you must continue to display my name and give me credit for writing the orginal program.


