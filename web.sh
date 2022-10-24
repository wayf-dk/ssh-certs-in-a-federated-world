#!/usr/bin/bash

rm -f sshfedresponse
mkfifo sshfedresponse
while true
do
    cat sshfedresponse | nc -l 7778 | (ssh -T -p 2022 sshca.lan > ~/.ssh/id_ed25519-cert.pub ; echo -e "HTTP/1.1 200\r\nAccess-Control-Allow-Origin: *\r\n\r\n" `ssh sshweblogin@sshsp.lan` > sshfedresponse)
done