# ssh server side stuff

## General stuff

Make sshfedloginshell.php executable

## /etc/ssh/sshd_config

```
TrustedUserCAKeys /srv/dev/ssh-certs-in-a-federated-world/ssh-server-side/ssh-ca-key.pub
AuthorizedPrincipalsCommandUser root
AuthorizedPrincipalsCommand /usr/bin/php /srv/dev/ssh-certs-in-a-federated-world/ssh-server-side/AuthorizedPrincipalsCommand.php %u %k %t
ExposeAuthInfo yes
AuthorizedKeysFile none
```

Remember to restart sshd

mkdir /var/run/sshca
chmod o+w /var/run/sshweblogin


## Special users

For initial login

`adduser --disabled-password --shell /srv/dev/ssh-certs-in-a-federated-world/ssh-server-side/sshfedloginshell.php sshfedlogin`

`adduser --disabled-password --shell /srv/dev/ssh-certs-in-a-federated-world/ssh-server-side/sshfedloginshell.php sshweblogin`


## For Weblogin


touch /home/sshweblogin/.hushlogin


```
AuthorizedKeysCommandUser root
AuthorizedKeysCommand /usr/bin/php /srv/dev/ssh-certs-in-a-federated-world/ssh-server-side/AuthorizedKeysCommand.php %u %k %t
```