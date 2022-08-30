# ssh server side stuff

for /etc/ssh/sshd_config

TrustedUserCAKeys <file with list of trusted ssh CA public keys>
AuthorizedPrincipalsCommandUser root
AuthorizedPrincipalsCommand /usr/bin/php AuthorizedPrincipalsCommand.php %u %k %t
