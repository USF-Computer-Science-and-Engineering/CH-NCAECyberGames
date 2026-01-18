#!/bin/bash 
export DEBIAN_FRONTEND=noninteractive

# this script mass adds users from the ftp scoring users file into the 
# filezilla server users xml file. 

# syntax: sudo filezilla_ftp_users_add.sh userlist.txt 


# Ensure an argument is provided
SETTINGS_FILE="/opt/filezilla-server/etc/settings.xml"
# this should be for the admin interface. Users added via this script should be able to login with their local credentials. 
# HOWEVER, if we have to install it manually, disable access to the admin interface via networks 
# the pw is CyberHerd2025!
SECURE_HASH="i+lktA6SvtIQd+j34he3K3ZhWh/129tgsoWjs23qF3Y"
SECURE_SALT="TEXyhStThhoeO+xQqmRZaemzAgYRKhmH4iuhqKllmJ8"
if [ -z "$1" ]; then
    echo "ERROR: No user list file provided."
    echo "Usage: sudo $0 <userlist.txt>"
    exit 1
fi

#echo -e "ADDING FTP USER TO ftp_users GROUP\n"
#sudo usermod -a -G ftp_users ftp
#echo -e "COMPLETE\n"

filename="$1"
filepath=$(readlink -f "$filename")

echo -e "ADDING USERS TO /opt/filezilla-server/etc/users.xml\n"
while read -r user; do
    sed -i "/<\/filezilla>/i \\
<user name=\"$user\" enabled=\"true\">\\
        <mount_point tvfs_path=\"/\" access=\"1\" native_path=\"\" new_native_path=\"/mnt/Files\" recursive=\"2\" flags=\"0\" />\\
        <rate_limits inbound=\"unlimited\" outbound=\"unlimited\" session_inbound=\"unlimited\" session_outbound=\"unlimited\" />\\
        <allowed_ips></allowed_ips>\\
        <disallowed_ips></disallowed_ips>\\
        <session_open_limits files=\"unlimited\" directories=\"unlimited\" />\\
        <session_count_limit>unlimited</session_count_limit>\\
        <description></description>\\
        <realm name=\"ftp\" status=\"enabled\" />\\
        <realm name=\"ftps\" status=\"disabled\" />\\
        <impersonation login_only=\"false\" />\\
        <methods>password</methods>\\
</user>
" /opt/filezilla-server/etc/users.xml
done < $filepath
echo -e "COMPLETE\n"

echo -e "VERIFYING CONTENT IN /opt/filezilla-server/etc/users.xml"
sudo cat /opt/filezilla-server/etc/users.xml | grep "user name"
echo -e "COMPLETE\n"

echo -e "ENABLING INSECURE FTP"
sudo sed -i "s|<tls_mode>.*</tls_mode>|<tls_mode>0</tls_mode>|g" /opt/filezilla-server/etc/settings.xml
echo -e "All <tls_mode> values replaced with 0 in: /opt/filezilla-server/etc/settings.xml"
echo -e "COMPLETE\n"

echo -e "CHANGING ADMINISTRATION INTERFACE PASSWORD TO SECURE ONE"
# Use sed to replace the hash and salt values in the XML file
sed -i "s|<hash>.*</hash>|<hash>$SECURE_HASH</hash>|g" "$SETTINGS_FILE"
sed -i "s|<salt>.*</salt>|<salt>$SECURE_SALT</salt>|g" "$SETTINGS_FILE"
echo -e "COMPLETE\n"

echo -e "RESTARTING FILEZILLA-SERVER\n"
sudo systemctl restart filezilla-server.service
echo -e "COMPLETE\n"
