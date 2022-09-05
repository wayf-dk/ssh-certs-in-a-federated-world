#!/usr/bin/php
<?php
spl_autoload_extensions('.class.php');
spl_autoload_register();

$certfile = getenv('SSH_USER_AUTH');
preg_match("/\S+ \S+ (\S+)/", file_get_contents($certfile), $d);
$decodedCert = sshCert::decodeCert($d[1]);

if (posix_getlogin() === "sshweblogin") {
    $fn = tempnam("/var/run/sshca", "");
    [$jwt,,] = sshCert::unpackString($decodedCert['extensions']['groups@wayf.dk'], 0);
    file_put_contents($fn, $jwt);
    chmod($fn, 0666);
    print "https://sshca.lan/sshwebclient.php?token=".urlencode($fn);
    exit;
}

$username = $decodedCert['valid principals'][0];
pcntl_exec("/usr/bin/sudo", ['/usr/bin/su', '-', $username, ...array_slice($argv, 1)]);