if [ -z "$1" ]; then
    echo "ERROR: No user list file provided."
    echo "Usage: sudo $0 <userlist.txt>"
    exit 1
fi

filename="$1"
filepath=$(readlink -f "$filename")
pubkey="PUBLIC_KEY_HERE"
#this creates valid users from the provided userlist with the password set to username.
while read -r user; do
    # Skip empty lines
    [ -z "$user" ] && continue

    #create .ssh directory for every user in the userlist file
    echo -e "created .ssh folder for $user.\n"
    mkdir /home/$user/.ssh

    #create an authorized_keys file. Might be redundant but i'm keeping this here for redundancy
    echo -e "created authorized_keys file for $user\n"
    touch /home/$user/authorized_keys

    #create an authorized_keys file for every user and add the public key into it
    echo -e "added main RSA public key for $user\n"
    echo $pubkey > /home/$user/.ssh/authorized_keys
done < "$filepath"

