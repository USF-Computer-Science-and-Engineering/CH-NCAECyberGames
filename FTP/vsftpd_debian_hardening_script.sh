#!/bin/bash
# ----------------------------------------------------------------------
# VSFTPD HARDENING SCRIPT (Debian-based systems with systemd)
# ----------------------------------------------------------------------
# Description:
#   - For vsftpd, anonymous login is disabled by default.
#   - This script creates an *allowed userlist* so that FTP denies
#     any logins not listed in /etc/vsftpd.userlist.
#
# Notes:
#   - Must be run with root privileges (sudo or as root).
#   - Assumes that all FTP login users are local users.
#   - The userlist file will be readable/writable only by root.
# ----------------------------------------------------------------------

# Ensure an argument is provided
if [ -z "$1" ]; then
    echo "ERROR: No user list file provided."
    echo "Usage: sudo $0 <userlist.txt>"
    exit 1
fi

# --- DISABLE ANONYMOUS USER IN CASE IT IS ENABLED ---
echo -e "\n[+] Disabling Anonymous login. The other anonymous options"
sudo sed -i "s|.*anonymous_enable.*|anonymous_enable=NO|g" /etc/vsftpd.conf
echo -e "COMPLETE\n"

# --- DISABLE OTHER ANONYMOUS OPTIONS ---
echo -e "\n[+] Disabling other options relating to anonymous login"
sudo sed -i "s|.*anon_upload_enable.*|anon_upload_enable=NO|g" /etc/vsftpd.conf
echo -e "COMPLETE\n"

# --- ALLOW CHROOT (change local root) ---
echo -e "\n[+] Enabling chroot"
sudo sed -i "s|.*chroot_local_user.*|chroot_local_user=YES|g" /etc/vsftpd.conf
echo -e "COMPLETE\n"

# --- ALLOW WRITEABLE CHROOT ---
echo -e "\n[+] Enabling writeable chroot"
sudo echo "allow_writeable_chroot=YES" >> /etc/vsftpd.conf
echo -e "COMPLETE\n"

# --- ALLOW WRITES TO FTP ROOT ---
echo -e "\n[+] Allowing write to FTP root"
sudo sed -i "s|.*write_enable.*|write_enable=YES|g" /etc/vsftpd.conf
echo -e "COMPLETE\n"

# --- CREATE USERLIST FILE ---
echo -e "\n[+] Creating userlist file: /etc/vsftpd.userlist"
sudo touch /etc/vsftpd.userlist
sudo chmod 600 /etc/vsftpd.userlist
echo "[+] Permissions set to root read/write only."
echo -e "COMPLETE\n"

# --- CREATE FTP ROOT IF IT ISN'T ALREADY MADE ---
echo -e "\n[+] Creating FTP root in /mnt/files if it doesn't exist already"
sudo mkdir -p /mnt/Files
echo -e "COMPLETE\n"

# --- CHANGE FTP ROOT TO /mnt/Files ---
echo -e "\n[+] Changing FTP root to: /mnt/files"
# assuming this directory already exists (the previous PDFs on FTP for cybergames implies that the directory, users and files already exist)
sudo echo "local_root=/mnt/Files" | sudo tee -a /etc/vsftpd.conf > /dev/null
echo -e "COMPLETE\n"

# --- CHANGE FTP ROOT PERMISSIONS ---
echo -e "\n[+] Changing FTP root directory permissions"
sudo chown -R nobody:ftp_users /mnt/Files # should change the permissions of /mnt/Files to nobody:ftp_users AND all of the contents within it 
	# to be owned by nobody and group as ftp_users 
sudo chmod 2070 /mnt/Files
echo -e "COMPLETE\n"

# --- MAKE SURE FTP_USERS GROUP CAN READ FILES CREATED BY SCORING USERS ---
echo -e "\n[+] Making sure ftp_users group can read files created by other scoring users"
# Check if local_umask already exists in the config file
if grep -q "^local_umask" /etc/vsftpd.conf; then
    # If it exists, change it to local_umask=007
    sudo sed -i "s|^local_umask.*|local_umask=007|g" /etc/vsftpd.conf
    echo -e "local_umask updated to 007"
else
    # If it doesn't exist, add it at the end of the file
    echo "local_umask=007" | sudo tee -a /etc/vsftpd.conf > /dev/null
    echo -e "local_umask added to vsftpd.conf"
fi
echo -e "COMPLETE\n"

# --- READ AND APPEND USERLIST ENTRIES ---
filename="$1"
filepath=$(readlink -f "$filename")

echo -e "[+] Reading usernames from: $filepath"
echo -e "[+] Adding usernames to /etc/vsftpd.userlist"
while read -r user; do
    echo "$user" | sudo tee -a /etc/vsftpd.userlist > /dev/null
done < "$filepath"
echo -e "COMPLETE\n"

# --- DISPLAY USERLIST FOR CONFIRMATION ---
echo "[+] vsftpd.userlist contents:"
sudo cat /etc/vsftpd.userlist
echo -e "\n"

# --- ENABLE USERLIST IN VSFTPD CONFIGURATION ---
echo "[+] Enabling userlist feature in /etc/vsftpd.conf"
echo -e "userlist_enable=YES\nuserlist_file=/etc/vsftpd.userlist\nuserlist_deny=NO" \
| sudo tee -a /etc/vsftpd.conf > /dev/null
echo -e "COMPLETE\n"

# --- DISPLAY CONFIRMATION OF CONFIG UPDATE ---
echo "[+] Last five lines of /etc/vsftpd.conf:"
sudo tail -n 5 /etc/vsftpd.conf
echo -e "\n"

# --- RESTART VSFTPD SERVICE ---
echo "[+] Restarting vsftpd service..."
sudo systemctl restart vsftpd.service
echo "[+] COMPLETE"



