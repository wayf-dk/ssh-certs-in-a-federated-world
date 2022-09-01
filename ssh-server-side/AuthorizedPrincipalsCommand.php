<?php
ini_set('error_log', "/var/log/sshcert.log");
spl_autoload_extensions('.class.php');
spl_autoload_register();

error_log(print_r($argv, TRUE));
[$sc, $username, $certificate, $type] = $argv;

$decodedCertificate = sshCert::decodeCert($certificate);
error_log(print_r($decodedCertificate, 1));

$certusername = jwt2passwd::updateUserAndGroup($decodedCertificate);

error_log("username: $username");

    print <<<eop
$certusername
eop;
