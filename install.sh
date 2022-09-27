#!/usr/bin/sh

cp go/cert1 /usr/local/bin/cert1

if [ "$1" = "CA" ]
then
cat > /etc/ssh/sshd_config.d/ca.conf <<eof
AuthorizedKeysCommandUser root
AuthorizedKeysCommand /usr/local/bin/cert1 AuthorizedKeysCommand %u %k %t
ExposeAuthInfo yes
eof
/usr/sbin/adduser -gecos "" --disabled-password --shell /usr/local/bin/cert1 sshgencert
mkdir -p /var/run/sshca
chown sshgencert:www-data /var/run/sshca
fi

if [ "$1" = "sshserver" ]
then
cat > /etc/ssh/sshd_config.d/certs.conf <<eof
TrustedUserCAKeys /etc/ssh/sshd_config.d/ca-keys.pub
AuthorizedPrincipalsCommandUser root
AuthorizedPrincipalsCommand /usr/local/bin/cert1 AuthorizedPrincipalsCommand %u %k %t
ExposeAuthInfo yes
#AuthorizedKeysFile none
eof

cat > /etc/ssh/sshd_config.d/ca-keys.pub <<eof
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJoDNr0ec0yRaDdr7NhQtJkaNNPF+QQkeINOFYlPaT0b
eof

cat > /etc/sudoers.d/10_sshfedlogin <<eof
sshfedlogin ALL=(root) NOPASSWD: /usr/bin/su
eof

/usr/sbin/adduser -gecos "" --disabled-password --shell /usr/local/bin/cert1 sshfedlogin
/usr/sbin/adduser -gecos "" --disabled-password --shell /usr/local/bin/cert1 sshweblogin
mkdir -p /var/run/sshcerts
chown sshweblogin:www-data /var/run/sshcerts
fi

systemctl restart sshd