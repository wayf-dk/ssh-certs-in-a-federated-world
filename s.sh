#!/bin/sh
key="$HOME/.ssh/id_ed25519"
now=$(date "+%Y-%m-%dT%H:%M:%S")
notafter=$(ssh-keygen -Lf "$key-cert.pub" | grep -oE '[-[:digit:]:T]{19}$')

[[ $now < $notafter ]] && exec ssh ${@}

function handleRequest() {
  read line
  token=$(echo $line | sed -E "s#.* /(.*) HTTP.*#\1#")
  ssh -i "$key.pub" -o IdentitiesOnly=yes sshgencert@sshca.lan $token | tr -d '[\r\n]' > "$key-cert.pub"
  cert=$(/usr/local/bin/ssh-keygen -Lf $key-cert.pub)
  echo -e "HTTP/1.1 200\r\nAccess-Control-Allow-Origin: *\r\n\r\n$cert" > response
}

rm -f response
mkfifo response
open 'https://sshca.lan/'
cat response | nc -l 7788 | handleRequest
exec ssh ${@}

