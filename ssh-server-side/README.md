# ssh server side stuff

for /etc/ssh/sshd_config


```
TrustedUserCAKeys /..../ssh-ca-kay.pub
AuthorizedPrincipalsCommandUser root
AuthorizedPrincipalsCommand /usr/bin/php /..../AuthorizedPrincipalsCommand.php %u %k %t
