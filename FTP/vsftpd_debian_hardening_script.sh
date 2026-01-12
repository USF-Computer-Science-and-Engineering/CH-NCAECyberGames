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
#   - Consider creating a ftp_users group that  owns /mnt/files and nobody else can read those files (TODO)
# ----------------------------------------------------------------------

# Ensure an argument is provided
if [ -z "$1" ]; then
    echo "ERROR: No user list file provided."
    echo "Usage: sudo $0 <userlist.txt>"
    exit 1
fi

# --- CREATE USERLIST FILE ---
echo -e "\n[+] Creating userlist file: /etc/vsftpd.userlist"
sudo touch /etc/vsftpd.userlist
sudo chmod 600 /etc/vsftpd.userlist
echo "[+] Permissions set to root read/write only."
echo -e "COMPLETE\n"

# --- CHANGE FTP ROOT TO /mnt/Files ---
echo -e "\n[+] Changing FTP root to: /mnt/files"
# assuming this directory already exists (the previous PDFs on FTP for cybergames implies that the directory, users and files already exist)
sudo echo "local_root=/mnt/files" | sudo tee -a /etc/vsftpd.conf > /dev/null
echo -e "COMPLETE\n"

# --- CHANGE FTP ROOT PERMISSIONS ---
sudo chown -R nobody:ftp_users /mnt/Files # should change the permissions of /mnt/Files to nobody:ftp_users AND all of the contents within it 
	# to be owned by nobody and group as ftp_users 
sudo chmod 2070 /mnt/Files

# TODO: make arbitrary check that changes all of the owners and groups for the existing files within FTP root. Include hidden files too

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
