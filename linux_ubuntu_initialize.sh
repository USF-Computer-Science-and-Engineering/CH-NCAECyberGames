#!/bin/bash

# update, upgrade and install fail2ban and ufw and hardens ssh 
# this script assumes the current machine has internet access

echo -e "This script is only meant to be run once, hence the initialize bit in the script! Run it with sudo privs\n"

sudo apt-get update -y
sudo apt-get upgrade -y # this should update the kernel? 
sudo apt install fail2ban ufw -y

# print out the kernel version
uname -a
echo -e "Is the kernel version between 5.8 and 5.17? If so, update the kernel manually.\n"

# check pwnkit 
cat /etc/os-release
apt-cache policy policykit-1
echo -e "Cross reference the information from os-release and the version of policykit installed\n"

# create backup of /etc/passwd in case i break something
sudo cp /etc/passwd /etc/passwd.bak

# disable root user --> should disable any logins to this user
sudo sed '1 s/^.*$/root:x:0:0:root:\/root:\/sbin\/nologin/' /etc/passwd

# return first line of /etc/passwd for sanity check
cat /etc/passwd | head -n 1


