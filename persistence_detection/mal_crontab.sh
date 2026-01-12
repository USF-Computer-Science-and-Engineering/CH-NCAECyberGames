#!/bin/bash

# this script detects any non-standard cron jobs for both system and users

# list all user and system cron jobs

echo -e "Listing all user and system cron jobs"
cron_jobs=$(sudo ls /var/spool/cron/crontabs/)

for user in $cron_jobs
do
  echo -e "USER: $user\n"
  cat /var/spool/cron/crontabs/$user | grep -v '^#'
done
