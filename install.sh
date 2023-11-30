#!/usr/bin/sh


for module in "$@"
do

case $module in
CA)
systemctl stop sshca
cp go/sshca /usr/local/bin/sshca

cat > /etc/systemd/system/sshca.service <<eof
[Unit]
Description=SSH CA Web

[Service]
ExecStart=/usr/local/bin/sshca
eof

systemctl start sshca
;;

sshserver)


cat > /etc/ssh/sshd_config.d/certs.conf <<eof
TrustedUserCAKeys /etc/ssh/sshd_config.d/ca-keys.pub
AuthorizedPrincipalsFile /etc/ssh/sshd_config.d/principals_%u
ExposeAuthInfo yes
#AuthorizedKeysFile none
eof

cat > /etc/ssh/sshd_config.d/ca-keys.pub <<eof
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJHbiNzbLVnqSOyCpaDnjBpNTKAS8PHBLhTeQtxCnMdu
eof


cat > /etc/ssh/sshd_config.d/principals_mz <<eof
madpe@dtu.dk
gikcaswid@orphanage.wayf.dk
eof

systemctl restart sshd
;;

sshfedlogin)
cp go/sshfedloginshell /usr/local/bin/sshfedloginshell

/usr/sbin/adduser -gecos "" --disabled-password --shell /usr/local/bin/sshfedloginshell sshfedlogin

cat > /etc/ssh/sshd_config.d/sshfedlogin.conf <<eof
#AllowUsers=sshfedlogin vagrant
eof

cat > /etc/sudoers.d/10_sshfedlogin <<eof
sshfedlogin ALL=(root) NOPASSWD: /usr/bin/su, /usr/sbin/adduser, /usr/sbin/addgroup, /usr/sbin/usermod
eof

systemctl restart sshd
;;

sshweblogin)
/usr/sbin/adduser -gecos "" --disabled-password --shell /usr/local/bin/sshwebloginshell sshweblogin

cp go/sshwebloginshell /usr/local/bin/sshwebloginshell
touch /home/sshweblogin/.hushlogin
mkdir -p /var/run/sshweblogin
chown sshweblogin:www-data /var/run/sshweblogin
;;

*)

echo "unknown module $module"
;;
esac
done
