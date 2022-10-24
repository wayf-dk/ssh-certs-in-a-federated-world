#!/bin/bash
open "https://sshca.lan?idplist=$1"
nc -l 7778 | ssh -T -p 2022 sshca.lan > ~/.ssh/id_ed25519-cert.pub
