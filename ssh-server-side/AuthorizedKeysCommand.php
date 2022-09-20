#!/usr/bin/php
<?php
ini_set('error_log', "/var/log/sshcert.log");

error_log(print_r($argv, TRUE));

[, $username, $key, $type] = $argv;

if ($type == "ssh-ed25519" && $username == "sshgencert") {
    error_log("$username $key $type OK");
    print "$type $key\n";
    exit;
}

print "\n";

