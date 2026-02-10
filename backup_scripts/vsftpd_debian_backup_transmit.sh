#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

#this should be run as root to avoid permission issues when backing up
# this script takes all files in the ftp root directory, zips it up, and sends it to a backup host through
# scp

# create a zip of the ftp root that includes all of the files in it
FTP_ROOT=/mnt/Files
DEBIAN_VSFTPD_CONF=/etc/vsftpd.conf
#REDHAT_VSFTPD_CONF=/etc/vsftpd/vsftpd.conf

# sanity checks
#arg1 = backup ip
if [ -z "$1" ]; then
    echo "ERROR: No backup IP provided."
    echo "Usage: sudo $0 BACKUP_IP BACKUP_PORT"
    exit 1
fi

#arg2 = backup port
if [ -z "$2" ]; then
    echo "ERROR: No backup port provided."
    echo "Usage: sudo $0 BACKUP_IP BACKUP_PORT"
    exit 1
fi


echo -e "zip file backup of ftp root created in current directory\n"
sudo zip -r backup.zip $FTP_ROOT $DEBIAN_VSFTPD_CONF

echo -e "transmitting backup zip to backup machine\n"
nc -q 0 $1 $2 < backup.zip
echo -e "SUCCESS"

# creates a backup from the variable FTP_ROOT. It is placed in the same directory the script is ran from
# send the newly created zip file to the remote location via netcat. 
# SSH may result in compromise of the backup machine. HTTP uploads from the ftp machine requires uploadserver
# installed + assuming that installs aren't possible due to no internet.

#instructions: 
#echo -e "run on receiving end: sudo bash -c 'nc -l 1234 > backup.zip'"
#echo -e "run on ftp machine: 'nc -q 0 backupmachine_ip 1234 < backup.zip'"




