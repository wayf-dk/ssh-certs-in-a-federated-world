#!/usr/bin/php
<?php
spl_autoload_extensions('.class.php');
spl_autoload_register();

$sshUserAuth = getenv('SSH_USER_AUTH');
preg_match("/\S+ (\S+ \S+)/", file_get_contents($sshUserAuth), $d);
$publickey = $d[1];

if (posix_getlogin() === "sshgencert") {
    $fn = "/var/run/sshca/".$argv[2];
    $attrs = json_decode(file_get_contents($fn), 1);
    unlink($fn);
    print genCert($publickey, $attrs);
    exit;
} else {
    $decodedCert = sshCert::decodeCert($publickey);
    if (posix_getlogin() === "sshweblogin") {
        $fn = tempnam("/var/run/sshca", "");
        [$jwt,,] = sshCert::unpackString($decodedCert['extensions']['groups@wayf.dk'], 0);
        file_put_contents($fn, $jwt);
        chmod($fn, 0666);
        $token = array_reverse(explode("/", $fn))[0];
        print "https://sshsp.lan/sshwebclient.php?token=$token";
        exit;
    } else {
        $username = $decodedCert['valid principals'][0];
        pcntl_exec("/usr/bin/sudo", ['/usr/bin/su', '-', $username, ...array_slice($argv, 1)]);
    }
}

function genCert($pubKey, $attrs) {
    $principal = preg_replace("/[^-a-z0-9]/", "_", $attrs['eduPersonPrincipalName'][0]);
    $privatekey = dirname(__DIR__)."/ssh-cert-php/ssh-ca-key";
    $pubfile = tempnam("/tmp", "pub-");
    file_put_contents($pubfile, $pubKey);
    $jsonattrs = json_encode($attrs);
    $out = `ssh-keygen -q  -O 'extension:xgroups@wayf.dk=$jsonattrs' -s '$privatekey' -n '$principal' -I '$principal' -V +1d $pubfile 2>&1`;
    $certfile = "$pubfile-cert.pub";
    $cert = file_get_contents($certfile);
    unlink($certfile);
    unlink($pubfile);
    return $cert;
}
