# disable root login for ssh server
#sudo sed -i "s|#PermitRootLogin.*|PermitRootLogin no|g" /etc/ssh/sshd_config
# not sure if we are going to use root login. Uncomment if we aren't. 

# disable password authentication (assuming everyone including scoring users login with a key/pubkey instead of a password)
sudo sed -i "s|#PasswordAuthentication.*|PasswordAuthentication no|g" /etc/ssh/sshd_config

# disable permit empty passwords
sudo sed -i "s|#PermitEmptyPasswords.*|PermitEmptyPasswords no|g" /etc/ssh/sshd_config

# enable public key authentication
sudo sed -i "s|#PubkeyAuthentication.*|PubkeyAuthentication yes|g" /etc/ssh/sshd_config

# change max auth tries
sudo sed -i "s|#MaxAuthTries.*|MaxAuthTries 3|g" /etc/ssh/sshd_config

# change max sessions. Note: i chose an arbitrary number for this. Change as needed
sudo sed -i "s|#MaxSessions.*|MaxSessions 4|g" /etc/ssh/sshd_config

# enable authorized_keys file thing
sudo sed -i "s|#AuthorizedKeysFile.*|AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2|g" /etc/ssh/sshd_config

# grep output to confirm changes
sudo cat /etc/ssh/sshd_config | grep -e "MaxSessions" -e "MaxAuthTries" -e "PubkeyAuthentication" -e "PasswordAuthentication" -e "PermitRootLogin" -e "AuthorizedKeysFile"
