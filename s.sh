#!/bin/bash
type="ed25519" ;
regexp='/([0-9a-f]+)'

function handleRequest() {
    read line
    [[ $line =~ $regexp ]]
    ssh ssh://sshca.lan:2022 ${BASH_REMATCH[1]} > ~/.ssh/id_$type-cert.pub ;
    echo -e "HTTP/1.1 200\r\n" > response
}

open "https://sshca.lan?idplist=$1"
cat response | nc -l 7778 | handleRequest