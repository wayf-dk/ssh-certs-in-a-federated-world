# ssh-certs-in-a-federated-world

POC for enabling ssh logins from a federated authentication by leveraging SSH certificates

For a general description of the use of SSH certificates se: https://smallstep.com/blog/use-ssh-certificates/

There are 3 roles at play:

1. The SSH Certificate Authority
2. The server(s) that will use the certificate for user authn
3. The client that logins to a server

## Creating user certificates

The SSH Certificate is a service in a federation and receives attributes/claims from an IdP. It
saves the attributes under a random name - a token. It then creates a ssh command - with the token as parameter -
that allows a special user to login and extract the actual user's public key. This allows the SSH CA to create a
SSH certificate from the attributes - that it has access to by way of the token - and the public key.

The SSH certificate is sent to stdout and thus made available on the client, where it is saved as a standard
SSH certificate.

## The SSH server

It is possible to set up a SSH server to just use SSH certificates as an authentication method if the user management is
already in place. It just requires adding a TrustedUserCAKeys parameter pointing to at file with the public keys/certificates
of the trusted SSH CAs.

You might want to add a "AuthorizedKeysFile none" as well to disallow the use of normal public keys in the
.ssh/authorized_keys or .ssh/authorized_keys2 files.

This POC includes the ability to create and update users depending on the content of the certificate.







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
TrustedUserCAKeys /etc/ssh/sshd_config.d/ssh-ca-key.pub
AuthorizedPrincipalsCommandUser root
AuthorizedPrincipalsCommand /usr/local/bin/cert1 AuthorizedPrincipalsCommand %u %k %t
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
AuthorizedKeysCommand /usr/local/bin/cert1 AuthorizedKeysCommand %u %k %t
ExposeAuthInfo yes
```