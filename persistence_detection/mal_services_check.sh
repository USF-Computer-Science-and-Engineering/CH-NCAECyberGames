#!/bin/bash
# This script checks if any .service files within /etc/systemd/system do not match against the predefined list
# of known good services. If there are services that don't match the predefined list, investigate.

all_services=$(ls /etc/systemd/system/*.service | xargs -n1 basename)
known_good_services=("cloud-init-network.service"
"dbus-fi.w1.wpa_supplicant1.service"
"dbus-org.bluez.service"
"dbus-org.freedesktop.Avahi.service"
"dbus-org.freedesktop.ModemManager1.service"
"dbus-org.freedesktop.nm-dispatcher.service"
"dbus-org.freedesktop.oom1.service"
"dbus-org.freedesktop.resolve1.service"
"dbus-org.freedesktop.thermald.service"
"dbus-org.freedesktop.timesync1.service"
"display-manager.service"
"syslog.service")

for service in $all_services
do
  if [[ " ${known_good_services[@]} " =~ " $service " ]]; then
      continue
  else
      echo -e "$service is not in the known good list! Investigate at: /etc/systemd/system/$service"
  fi
done
