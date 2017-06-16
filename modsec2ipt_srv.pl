#!/usr/bin/perl
###########################################################
# modsec2ipt_srv.pl
#
# (c) Jerome Bruandet - 01/2009
#
# Doc : http://spamcleaner.org/en/misc/modsec2ipt.html
#
# server used to block Ip with iptables and mod_security.
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
