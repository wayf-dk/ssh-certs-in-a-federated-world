# ssh server side stuff

## General stuff

Make sshfedloginshell.php executable

## /etc/ssh/sshd_config

```
TrustedUserCAKeys /srv/dev/ssh-certs-in-a-federated-world/ssh-server-side/ssh-ca-key.pub
AuthorizedPrincipalsCommandUser root
AuthorizedPrincipalsCommand /usr/bin/php /srv/dev/ssh-certs-in-a-federated-world/ssh-server-side/AuthorizedPrincipalsCommand.php %u %k %t
ExposeAuthInfo yes
```

Remember to restart sshd

## Special users

For initial login

`adduser --disabled-password --shell /srv/dev/ssh-certs-in-a-federated-world/ssh-server-side/sshfedloginshell.php sshfedlogin`

`adduser --disabled-password --shell /srv/dev/ssh-certs-in-a-federated-world/ssh-server-side/sshfedloginshell.php sshweblogin`

touch /home/sshweblogin/.hushlogin

## For Weblogin

mkdir /var/run/sshweblogin
chmod o+w /var/run/sshweblogin