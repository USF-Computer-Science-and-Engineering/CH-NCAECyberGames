#vars
SMB_ROOT='/mnt/files'

if [[ $EUID -ne 0 ]]; then
    echo -e "This script must be run as root (use sudo)."
    exit 1
fi

# add smb root to selinux exceptions
semanage fcontext -a -t samba_share_t "$SMB_ROOT(/.*)?"
restorecon -Rv $SMB_ROOT

# backup existing SMB config into /root
cp /etc/samba/smb.conf /root/smb.conf.bak
echo -e "INFO: backed up smb.conf to /root"


# overwrite existing smb config with existing one
echo "W2dsb2JhbF0KCXdvcmtncm91cCA9IFNBTUJBCglzZWN1cml0eSA9IHVzZXIKCglwYXNzZGIgYmFja2VuZCA9IHRkYnNhbQoKCSMgSW5zdGFsbCBzYW1iYS11c2Vyc2hhcmVzIHBhY2thZ2UgZm9yIHN1cHBvcnQKCWluY2x1ZGUgPSAvZXRjL3NhbWJhL3VzZXJzaGFyZXMuY29uZgoJbWluIHByb3RvY29sID0gU01CMgoJcmVzdHJpY3QgYW5vbnltb3VzID0gMgoJZ3Vlc3Qgb2sgPSBubwoJc2VydmVyIHNpZ25pbmcgPSBtYW5kYXRvcnkJCltwcm90b3R5cGVdCglndWVzdCBvayA9IG5vCgl3cml0ZWFibGUgPSB5ZXMKCWJyb3dzZWFibGUgPSB5ZXMKCXBhdGggPSAvbW50L2ZpbGVzCgljb21tZW50ID0gU01CIHNoYXJlcyB0ZXN0CgljcmVhdGUgbWFzayA9IDA2NjAKCWRpcmVjdG9yeSBtYXNrID0gMDc3MAoJcmVhZCBvbmx5ID0gbm8KCXZhbGlkIHVzZXJzID0gQHNtYl91c2VycwoJZm9yY2UgZ3JvdXAgPSBzbWJfdXNlcnMK" | base64 -d > /etc/samba/smb.conf
echo -e "INFO: overwritten smb.conf to secure config"

echo -e "INFO: you will need to modify the existing configuration so that the remaining information fits\! But it should be secure right off the bat"

systemctl restart smb nmb

# allow smb in firewall
firewall-cmd --permanent --add-service=samba
firewall-cmd --reload
echo -e "INFO: added samba to firewall allow"

# tell user to manually sync user passwords to smbpasswd"
echo -e "INFO: sync user passwords to smbpasswd!"

echo -e "INFO: If smb root isn't configured already, chown it to nobody:smb_users and then chmod it to 770"

# create zip archive backup of samba sensitive files
zip -r samba_backup.zip /etc/samba /var/lib/samba #saves in current dir
echo -e "INFO: created backup of sensitive samba files. SCP THESE TO BACKUP SERVER IMMEDIATELY!"
cp samba_backup.zip /root 
echo -e "INFO: local backup saved"
