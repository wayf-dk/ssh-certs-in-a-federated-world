#!/usr/local/bin/php
<?php

//`open https://sshca.lan/`;
$socket = stream_socket_server('tcp://127.0.0.1:7780', $errno, $errstr);
for (;;) {
    $conn = stream_socket_accept($socket, 3600);
    $res = fread($conn, 65536);
    if (preg_match("/cmd=([^&\s]*)/", $res, $d)) {
        $cmd = urldecode($d[1]);
        $returnurl = `$cmd`;
        print "#$returnurl#\n";
        fwrite($conn, "HTTP/1.1 301 OK\r\nlocation: $returnurl\r\n\r\n");
    } elseif (preg_match("/url=([^&\s]*)/", $res, $d)) {
        $url = urldecode($d[1]);
        `$url`;
        $cert = `ssh-keygen -Lf "\$HOME/.ssh/id_ed25519-cert.pub"`;
        fwrite($conn, "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\n$cert\r\n");
    }
    fclose($conn);
}