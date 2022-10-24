<?php
header('content-type: text/plain');
$fn = "/var/run/sshweblogin/".$_GET['token'];
print_r(json_decode(file_get_contents($fn), 1));
unlink($fn);