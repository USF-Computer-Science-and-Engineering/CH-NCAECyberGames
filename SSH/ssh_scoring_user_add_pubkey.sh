#!/bin/bash

# Ensure the script is run as root to modify other users' homes
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (sudo)."
   exit 1
fi

if [ -z "$1" ]; then
    echo "ERROR: No user list file provided."
    echo "Usage: sudo $0 <userlist.txt>"
    exit 1
fi

filename="$1"
filepath=$(readlink -f "$filename")
# Replace the string below with your actual public key
pubkey="INSERT_PROVIDED_KEY_HERE"
# you might need to use -i thing for it to work

while read -r user || [ -n "$user" ]; do
    # Skip empty lines and comments
    [[ -z "$user" || "$user" =~ ^# ]] && continue

    # Define paths for clarity
    user_home="/home/$user"
    ssh_dir="$user_home/.ssh"
    auth_file="$ssh_dir/authorized_keys"

    # Check if user exists on the system before proceeding
    if ! id "$user" &>/dev/null; then
        echo "Skipping $user: User does not exist."
        continue
    fi

    # 1. Create .ssh directory if it doesn't exist
    if [ ! -d "$ssh_dir" ]; then
        mkdir -p "$ssh_dir"
        echo "Created .ssh folder for $user."
    fi

    # 2. Add the public key if it's not already in the file
    # We use grep to avoid duplicating the key if the script runs twice
    if [ ! -f "$auth_file" ] || ! grep -qF "$pubkey" "$auth_file"; then
        echo "$pubkey" >> "$auth_file"
        echo "Added public key to $user's authorized_keys."
    else
        echo "Key already exists for $user. Skipping append."
    fi

    # 3. Fix Permissions (Crucial for SSH to work)
    # SSH will reject keys if permissions are too 'open'
    chown -R "$user":"$user" "$ssh_dir"
    chmod 700 "$ssh_dir"
    chmod 600 "$auth_file"

    echo -e "Finished setup for $user.\n"

done < "$filepath"
