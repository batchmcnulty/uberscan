#!/bin/bash
echo "Batch file to install UBERSCAN and its dependencies."
echo "Pausing to give you a chance to cancel."
echo "- Remember, I need to be run with Superuser priveliges."
echo "So if you didn't sudo me, hit CTRL-C and do that."
echo "Otherwise simply wait one minute and I'll start work!"
sleep 1m
echo "."
echo "Added this 4th Now 2017 to make it compatible with Raspberry Pies and other computers"
sudo cpan HTTP::Request
echo " ************ INSTALLED HTTP::Request ********************"
echo " ************ INSTALLED HTTP::Request ********************"
echo " ************ INSTALLED HTTP::Request ********************"
echo " ************ INSTALLED HTTP::Request ********************"



sudo cpan IO::Socket::INET
echo " ******** INSTALLED IO::Socket::INET ***********************"
echo " ******** INSTALLED IO::Socket::INET ***********************"
echo " ******** INSTALLED IO::Socket::INET ***********************"
echo " ******** INSTALLED IO::Socket::INET ***********************"
ec
e
sleep 3
#sudo cpan IO-Socket-Timeout
sudo cpan IO::Socket::Timeout
echo " ******************* INSTALLED IO::Socket::Timeout ********************"
echo " ******************* INSTALLED IO::Socket::Timeout ********************"
echo " ******************* INSTALLED IO::Socket::Timeout ********************"
echo " ******************* INSTALLED IO::Socket::Timeout ********************"

sleep 3
sudo cpan Net::Telnet
echo " **********************INSTALLED Net::Telnet ***********************"
echo " **********************INSTALLED Net::Telnet ***********************"
echo " **********************INSTALLED Net::Telnet ***********************"
echo " **********************INSTALLED Net::Telnet ***********************"
sleep 3

sudo cpan Authen::Ntlm
echo "**************************** INSTALLED Authen::Ntlm ***************************"
echo "**************************** INSTALLED Authen::Ntlm ***************************"
echo "**************************** INSTALLED Authen::Ntlm ***************************"
echo "**************************** INSTALLED Authen::Ntlm ***************************"
sleep 3

sudo cpan Net::FTP

echo " ******************************** INSTALLED Net::FTP *******************************"
echo " ******************************** INSTALLED Net::FTP *******************************"
echo " ******************************** INSTALLED Net::FTP *******************************"
echo " ******************************** INSTALLED Net::FTP *******************************"
sleep 3

sudo cpan Net::POP3
# sudo cpan install Net::POP3::Perl
echo " ******************************** INSTALLED Net::POP3 *******************************"
echo " ******************************** INSTALLED Net::POP3 *******************************"
echo " ******************************** INSTALLED Net::POP3 *******************************"
echo " ******************************** INSTALLED Net::POP3 *******************************"
sleep 3

echo "******** ATTENTION!! INSTALLING THE POS THAT IS CURL"
echo "Any problems, uncomment some lines"
sudo apt-get install curl
sudo apt-get install libcurl4-gnutls-dev
sudo cpan WWW::Curl::Easy
echo "***************************************************"
echo " ARE YOU SEEING AN ERROR MESSAGE?" 
echo "If so, try each of the following, then try again:"
echo "    sudo apt-get install libcurl4-doc "
echo "    sudo apt-get install libcurl3-dbg "
echo "    sudo apt-get install libgnutls-dev"
echo "    sudo apt-get install libidn11-dev"
echo "    sudo apt-get install libkrb5-dev "
echo "    sudo apt-get install libldap2-dev"
echo "    sudo apt-get install librtmp-dev" 
echo "    sudo apt-get install zlib1g-dev"
echo "if you don't want to run this whole install script again the relevant"
echo "command is:"
echo "    sudo cpan WWW::Curl::Easy"
echo " "
echo "***********************************************"
echo "Giving you a minute to digest all that..."
sleep 60

echo "**************************** INSTALLED WWW::Curl::Easy (probably) ******************************"
echo "**************************** INSTALLED WWW::Curl::Easy (probably) ******************************"
echo "**************************** INSTALLED WWW::Curl::Easy (probably) ******************************"
echo "**************************** INSTALLED WWW::Curl::Easy (probably) ******************************"
echo ""
echo "*********** WARNING:  ********************************************************"
echo "* Curl::Easy is a fecker to install! If it doesn't work, try running one or  *"
echo "* all of the following commands, then run this script again:		   *"
echo "*    sudo apt-get install libcurl4-doc					   *"
echo "*    sudo apt-get install libcurl3-dbg					   *"
echo "*    sudo apt-get install libgnutls-dev					   *"
echo "*    sudo apt-get install libidn11-dev					   *"
echo "*    sudo apt-get install libkrb5-dev					   *"
echo "*    sudo apt-get install libldap2-dev					   *"
echo "*    sudo apt-get install librtmp-dev					   *" 
echo "*    sudo apt-get install zlib1g-dev					   *"
echo "******************************************************************************"
echo "Waiting 20 seconds for you to read this message..."
sleep 20
sudo cpan Net::SSH::Expect
echo " ***************************** INSTALLED Net::SSH::Expect **************************"
echo " ***************************** INSTALLED Net::SSH::Expect **************************"
echo " ***************************** INSTALLED Net::SSH::Expect **************************"
echo " ***************************** INSTALLED Net::SSH::Expect **************************"
echo ""
echo "All done! Just one more thing...."
echo " "
echo "If you want to do SSH scanning with this baby add the following to /etc/ssh/ssh_config "
echo "(the 'Host *' line may already exist):"
echo " "
echo "Host *"
echo "    StrictHostKeyChecking no"
echo "    UserKnownHostsFile=/dev/null"
echo " "
echo " Copying uberscan.pl into /usr/bin... "
sudo chmod +777 uberscan.pl
sudo cp uberscan.pl /usr/bin/uberscan
echo " Done. Bye now!"
