#!/usr/bin/php
<?php
spl_autoload_extensions('.class.php');
spl_autoload_register();

preg_match("/\S+ \S+ (\S+)/", file_get_contents(getenv('SSH_USER_AUTH')), $d);
$decodedCert = sshCert::decodeCert($d[1]);
print "https://www.wayf.dk";
//print_r($decodedCert);
exit;
$username = $decodedCert['valid principals'][0];
//print $username;
pcntl_exec("/usr/bin/sudo", ['/usr/bin/su', '-', $username]);