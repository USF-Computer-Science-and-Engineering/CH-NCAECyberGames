#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
#set -x # THIS IS FOR DEBUG PURPOSES. LEAVE DISABLED

# REPLACE THIS HASH WITH THE ONE THEY PROVIDE. THIS IS JUST THE ONE FROM NOTION
secure_hash='$6$iB45nMgzciz4NZ6A$hus0EIqQG7K/W3LmpC9qbhlB5B1q6KcXExvrAv1vfL3XbvLtU92ItaB0E3nmRh1HUYQxWydEUFkbgjSGqgpl0/'
filename="$1"
filepath=$(readlink -f "$filename")


if [ -z "$1" ]; then
    echo "ERROR: No user list file provided."
    echo "Usage: sudo $0 <userlist.txt>"
    exit 1
fi

# Basic sanity check
if [ -z "$secure_hash" ]; then
  echo "secure_hash is empty. Set secure_hash to the precomputed encrypted hash." >&2
  exit 2
fi

#this creates valid users from the provided userlist with the password set to username. THE PASS IS TEMPORARY
#note: this creates users locally. A dedicated script for creating local users for scoring isn't necessary.
while read -r user; do
    # Skip empty lines
    [ -z "$user" ] && continue

    # If user does NOT exist
    if ! id "$user" &>/dev/null; then
        sudo useradd -m "$user"
        echo "$user:$secure_hash" | sudo chpasswd -e
        echo "  Created user: $user with predefined hash."
    else
        echo "  WARNING: '$user' already exists."
    fi
done < "$filepath"

#UNUSED. If you need to do /etc/shadow surgery, just...uncomment all this
# make backup of /etc/shadow in case we break something
#echo -e "CREATING BACKUP OF /ETC/SHADOW"
#sudo cp -p /etc/shadow /etc/shadow.bak
# this backup should preserve the permissions. No tomfoolery with the perms needed here.
#echo -e "DONE\n"



