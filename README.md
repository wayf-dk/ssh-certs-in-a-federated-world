# ssh-certs-in-a-federated-world
POC for doing enabling ssh logins from a federated authentication

## Creating user certificates



## Managing users on the the ssh server

### Just enabling ssh login based on ssh user certificates for existing users

Add a

TrustedUserCAKeys <name of file with list of public keys for trusted ssh CAs>

to /etc/ssh/sshd_config

The username must be listed in the principals part of the ssh certificate for the user as well

Sshd logs the certificate's Key ID and Serial.

### Create a user on-the-fly based on information in the certificate



