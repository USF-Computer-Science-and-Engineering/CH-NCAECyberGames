#!/bin/bash
# ======================================================
# FTP USER GROUP CREATION SCRIPT
# ------------------------------------------------------
# Description:
#   This script creates a dedicated 'ftp_users' group
#   and adds users (from a provided list file) to it.
#
# Requirements:
#   - Must be run with root privileges
#   - Takes one argument: the path to the user list file
#
# Usage:
#   sudo ./ftp_group_setup.sh userlist.txt
# ======================================================

# Ensure an argument is provided
if [ -z "$1" ]; then
    echo "ERROR: No user list file provided."
    echo "Usage: sudo $0 <userlist.txt>"
    exit 1
fi

filename="$1"
filepath=$(readlink -f "$filename")

echo -e "CREATING FTP USERS GROUP (ftp_users)"
sudo groupadd ftp_users 2>/dev/null || echo "Group 'ftp_users' already exists."
echo -e "COMPLETE\n"

echo -e "ADDING USERS FROM '$filepath' TO ftp_users GROUP"
while read -r user; do
    if id "$user" &>/dev/null; then
        sudo usermod -a -G ftp_users "$user"
        echo "  Added user: $user"
    else
        echo "  WARNING: User '$user' does not exist on this system."
    fi
done < "$filepath"
echo -e "COMPLETE\n"

# if for some reason you cannot list files as an authenticated user, uncomment the next three lines
#echo -e "ADDING FTP USER TO FTP_USERS GROUP\n"
#sudo usermod -a -G ftp_users ftp
#echo -e "COMPLETE\n"

echo -e "VERIFYING USERS IN ftp_users GROUP"
sudo getent group ftp_users
echo -e "COMPLETE\n"
