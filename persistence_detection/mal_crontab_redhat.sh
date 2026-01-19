#!/bin/bash

# this script detects any non-standard cron jobs for both system and users

# this is a variant of mal_crontab.sh for rocky8/redhat distros 

# list all user and root cron jobs

echo -e "Listing all user and system cron jobs"
cron_jobs=$(sudo ls /var/spool/cron/)

for user in $cron_jobs
do
  echo -e "USER: $user\n"
  cat /var/spool/cron/$user | grep -v '^#'
done
