#!/usr/bin/perl
###########################################################
# modsec2ipt.pl
#
# (c) Jerome Bruandet - 01/2009
#
# Doc : http://spamcleaner.org/en/misc/modsec2ipt.html
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

