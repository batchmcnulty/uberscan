echo "Scans for Mirai vulnerable boxes."
echo "This one uses wordlist files to sequentially search your LAN for Mirai-vulnerable IoT boxes."

uberscan -userfile:mirai-usernames.txt -passfile:mirai-passwords.txt -scantype:telnet -debug -ipblock:192.168/16
uberscan -user:root -passblank -scantype:telnet -debug -ipblock:192.168/16 
uberscan -user:admin -passblank -scantype:telnet -debug -ipblock:192.168/16
