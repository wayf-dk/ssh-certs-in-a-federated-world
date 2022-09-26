# ssh-certs-in-a-federated-world

POC for enabling ssh logins from a federated authentication by leveraging SSH certificates

For a general description of the use of SSH certificates se: https://smallstep.com/blog/use-ssh-certificates/

There are 3 roles at play:

1. The SSH Certificate Authority
2. The server(s) that will use the certificate for user authn
3. The client that logins to a server

The SSH Certificate is a service in a federation and receives attributes from an IdP. It then
saves the attributes under a random name - a token - and then makes the token available to it's
web frontend.



..


The ssh server

## Creating user certificates





## Managing users on the the ssh server

### Just enabling ssh login based on ssh user certificates for existing users

Add a

TrustedUserCAKeys <name of file with list of public keys for trusted ssh CAs>

to /etc/ssh/sshd_config

The username must be listed in the principals part of the ssh certificate for the user as well

Sshd logs the certificate's Key ID and Serial.

### Create a user on-the-fly based on information in the certificate


###

If you run ssh-add while a certificate is present it will be added to the ssh agent. Ssh will the keep using the certificate from the agent and no


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