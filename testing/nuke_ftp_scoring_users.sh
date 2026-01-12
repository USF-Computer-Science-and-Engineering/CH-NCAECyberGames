#!/bin/bash

# List of users to delete
users=(
  "gaston_chasseloup"
  "leon_serpollet"
  "william_vanderbilt"
  "henri_fournier"
  "maurice_augieres"
  "arthur_duray"
  "henry_ford"
  "louis_rigolly"
  "pierre_caters"
  "paul_baras"
  "victor_hemery"
  "fred_marriott"
  "lydston_hornsted"
  "kenelm_guinness"
  "rene_thomas"
  "ernest_eldridge"
  "malcolm_campbell"
  "ray_keech"
  "john_cobb"
  "dorothy_levitt"
  "paula_murphy"
  "camille_jenatzy"
)

# Loop through each user and delete
for user in "${users[@]}"; do
  sudo userdel "$user" && echo "User $user deleted successfully" || echo "Failed to delete user $user or user does not exist"
done

# print /etc/shadow
sudo cat /etc/shadow
