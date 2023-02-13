#!/bin/bash
[ ! -z "$1" ] && idplist="?idplist=$1"
open "https://ssh-cert.dgw.deic.dk/idpentityid=$IDP"; nc -l 7778 | ssh -T -p 2022 service.deic.dk zzz > ~/.ssh/id_deic-sshca-cert.pub-cert.pub
