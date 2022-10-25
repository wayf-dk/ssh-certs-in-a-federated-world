#!/bin/bash
[ ! -z "$1" ] && idplist="?idplist=$1"
open "https://sshca.lan$idplist"
nc -l 7778 | ssh -T -p 2022 sshca.lan > ~/.ssh/id_ed25519-cert.pub
