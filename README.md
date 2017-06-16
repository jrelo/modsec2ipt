# modsec2ipt
Mirror of http://spamcleaner.org/en/misc/modsec2ipt.tgz

Security : Linux : communication between mod_security and iptables to block IP's

iptables and mod_security are both very useful applications to protect a server but they cannot communicate with each other to block IP's in real time, mod_security being an apache module, it inherits its privileges.
However, it is easy to solve this problem with a simple client/server written in Perl.

Overview :

Upon detection, mod_security can perform several actions, amongst them redirection or program/script execution. Here, we will use the latter.
mod_security will launch a small Perl scrip (the client) and forward the IP address through the $ENV{'REMOTE_ADDR'} environment variable. Since this script must have apache privileges in order to be launched by mod_security, and hence not able to access iptables, it will connect to the second script (the server) which will run the iptables command to block the offending IP. The server doesn't need to be a deamon, it can simply be started by xinetd.

For that example, we will assume that your HTTP directory is /var/www/httpd.

The client :

It has to be copied to your apache web root directory. It should in no way be directly accessible to anyone (ie to a visitor with its browser).
Chmod it to 0755 and give it apache's rights (usually chown 33:33) so that mod_security could run it : 

 /var
   |---/www
     |--- modsec2ipt.pl    -rwxr-xr-x    www-data www-data
     |--- /cgi-bin
     |--- /httpd


 Important : never attempt to authorize Apache to have a direct access to iptables (sudoers, privileges modification etc) : in case of vulnerabilities in your HTTP pages a hacker could have full access to your firewall and could do whatever he wants ! If an attacker could still gain access to the modsec2ipt.pl script, he would be blacklisted as soon as he try to run it (the script doesn't accept any parameters and would send the client remote IP to iptables).

The client script (modsec2ipt.pl) :


#!/usr/bin/perl
###########################################################
# modsec2ipt.pl
#
# client executed by mod-security to connect to the server
# script which will blacklist the offending IP with iptables
#
###########################################################

# server port (modsec2ipt_srv.pl) :
$port = '54545';

###########################################################

use Socket;

# IP is forwarded by mod_security :
$USER_IP=$ENV{'REMOTE_ADDR'};

goto QUIT if (!$USER_IP);

eval {
   local $SIG{ALRM} = sub { die "alarm\n" };
   alarm 10;
   $proto = getprotobyname('tcp');
   socket(SOCK, PF_INET, SOCK_STREAM, $proto);
   $iaddr = gethostbyname('127.0.0.1');
   $sin = pack('Sna4x8', AF_INET, $port, $iaddr);
   connect(SOCK, $sin);
   recv SOCK, $res, 512, 0;
   alarm 0;
};
goto QUIT if ($@ =~ /alarm/);
goto CLOSE if ($res !~ /^OK/);

# send IP :
send SOCK, "$USER_IP\r\n", 0;
recv SOCK, $res, 512, 0;
CLOSE:
send SOCK, "QUIT\r\n", 0;
recv SOCK, $res, 100, 0;
close SOCK;

QUIT:
# STDOUT needed by mod_security :
print ".";
exit;

mod_security rules :
We have to add the execution of the client script to mod_security rules.
As an example, I will take a rule that blocks a vulnerability scanner that is often found in apache logs : 
  GET /sumthin HTTP/1.0
We add the call to our client script with the exec parameter.
- For mod_security v1.9.x : 

  SecFilter "^GET \/sumthin" "log,exec:/var/www/modsec2ipt.pl"

- For mod_security v2.x : 

  SecRule REQUEST_URI "\/sumthin" "log,exec:/var/www/modsec2ipt.pl"

Restart apache so that it will apply the new rules.
The server :

The server script, modsec2ipt_srv.pl which can be downloaded at the bottom of this article, has to be copied to the /usr/bin directory, chmoded 755 and owned by root (chown 0:0). 
It will be launched by xinetd. If it is not already installed on your machine, it is a good opportunity to do it now : 
  apt-get install xinetd

Create a /etc/xinetd.d/modsec2ipt file and add the following lines : 

  service modsec2ipt
  {
    flags         = NAMEINARGS
    socket_type   = stream
    protocol      = tcp
    wait          = no
    user          = root
    server        = /usr/sbin/tcpd
    server_args   = /usr/bin/modsec2ipt_srv.pl
    only_from     = 127.0.0.1
  }


Open /etc/services and add the reference to the server port : 

  modsec2ipt   54545/tcp


Restart xinetd : 

  # /etc/init.d/xinetd restart


Ensure that you can telnet to the server : 

  # telnet localhost 54545

  Trying 127.0.0.1...
  Connected to localhost.
  Escape character is '^]'.
  OK modsec2ipt server

Type 'QUIT' to close the connection.
By default, the server uses an iptables chain named 'MODSEC2IPT'. You do not have to create it, the server will do that itself. IP blocking is done only for the HTTP port (80) but you can easily change that in the script.

The server script (/usr/bin/modsec2ipt_srv.pl) :


#!/usr/bin/perl
###########################################################
# modsec2ipt_srv.pl
#
# server used to block IPs with iptables and mod_security.
# uses/creates the chain "MODSEC2IPT"
#
###########################################################
$chain = "MODSEC2IPT";
# blocked IP's log :
$log  = '/var/log/modsec2ipt.log';
# errors log :
$error_log='/var/log/modsec2ipt_error.log';
###########################################################

# check if our chain exists :
`iptables -L $chain >/dev/null 2>&1`;
$res = ( $? >> 8);
if ($res) {
   # create it :
   `iptables -N $chain 2>/dev/null`;
   `iptables -I INPUT -p tcp --dport 80 -j $chain 2>/dev/null`;
}
$date=`date '+%b %e %X'`;
chomp $date;
$|=1;
select(STDOUT);
print "OK, modsec2ipt server\x0D\x0A";
eval {
   local $SIG{ALRM} = sub { die "TIMEOUT\n" };
   alarm(10);
   while (<STDIN>){
      alarm(0);
      chomp;chop if /\r$/;
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
         `iptables -I $chain -s $_ -j DROP 2>/dev/null`;
         $res = ( $? >> 8);
         if ($res) {
            print "ERR #1\x0D\x0A";
            open LOG,">>$error_log";
            print LOG "$date cannot block [$_]\n";
            close LOG;
         }else{
            print "OK\r\n";
            open LOG,">>$log";
            print LOG "$date $_\n";
            close LOG;
         }
      }elsif (/^QUIT/i){
         print "OK\r\n";
         last;
      }else{ print "ERR : #2\x0D\x0A"; }
   }
};
print "ERR : timed-out\x0D\x0A" if( $@=~/TIMEOUT/ );

exit(0);

Test :

Start your browser and type : http://your_website.tld/sumthin
Then, try to reload the page : normally, you should be blocked : 

 # iptables -L MODSEC2IPT -nvx

    Chain MODSEC2IPT (1 references)
    pkts      bytes target   prot opt in     out     source               destination
      18     5972 DROP       all  --  *      *      YOUR_IP_ADDRESS        0.0.0.0/0

Flushing the rules :

It is hardly conceivable to keep IP's blocked indefinitely. Create a crontab job that will flush the rules and unblock IP's, say, every 15 minutes or so : 

   echo "14,29,44,59 * * * * root /sbin/iptables -F MODSEC2IPT >/dev/null" \
   >/etc/cron.d/modsec2ipt.cron
