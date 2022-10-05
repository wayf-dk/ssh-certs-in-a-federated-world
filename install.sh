#!/usr/bin/sh

if [ "$1" = "CA" ]
then
cp go/sshca /usr/local/bin/sshca
cp go/sshgencertshell /usr/local/bin/sshgencertshell
cp go/authorizedKeysCommand /usr/local/bin/authorizedKeysCommand
/usr/sbin/adduser -gecos "" --disabled-password --shell /usr/local/bin/sshgencertshell sshgencert
mkdir -p /var/run/sshca
chown sshgencert:www-data /var/run/sshca

cat > /etc/ssh/sshd_config.d/ca.conf <<eof
AuthorizedKeysCommandUser root
AuthorizedKeysCommand /usr/local/bin/authorizedKeysCommand %u %k %t
ExposeAuthInfo yes
eof
fi
systemctl restart sshd

if [ "$1" = "sshserver" ]
then
cat > /etc/ssh/sshd_config.d/certs.conf <<eof
TrustedUserCAKeys /etc/ssh/sshd_config.d/ca-keys.pub
ExposeAuthInfo yes
#AuthorizedKeysFile none
eof

cat > /etc/ssh/sshd_config.d/ca-keys.pub <<eof
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJoDNr0ec0yRaDdr7NhQtJkaNNPF+QQkeINOFYlPaT0b
eof

cat > /etc/ssh/sshd_config.d/ca-banner.txt <<eof
login at https://sshca.lan
eof

systemctl restart sshd

fi

if [ "$1" = "sshfedlogin" ]
then
cp go/sshfedloginshell /usr/local/bin/sshfedloginshell

/usr/sbin/adduser -gecos "" --disabled-password --shell /usr/local/bin/sshfedloginshell sshfedlogin

cat > /etc/sudoers.d/10_sshfedlogin <<eof
sshfedlogin ALL=(root) NOPASSWD: /usr/bin/su, /usr/sbin/adduser, /usr/sbin/addgroup, /usr/sbin/usermod
eof

fi

if [ "$1" = "sshweblogin" ]
then
/usr/sbin/adduser -gecos "" --disabled-password --shell /usr/local/bin/sshwebloginshell sshweblogin

cp go/sshwebloginshell /usr/local/bin/sshwebloginshell
touch /home/sshweblogin/.hushlogin

fi

