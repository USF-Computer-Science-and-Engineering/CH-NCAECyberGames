#!/bin/bash

# Path to the FileZilla Server settings.xml file
SETTINGS_FILE="/opt/filezilla-server/etc/settings.xml"

# Check if the settings.xml file exists
if [[ ! -f "$SETTINGS_FILE" ]]; then
    echo "Error: settings.xml file not found at $SETTINGS_FILE."
    exit 1
fi

# Define the new values to set
BAN_DURATION="300000"  # 300000 milliseconds (5 minutes)
LOGIN_FAILURE_TIME_WINDOW="60000"  # 60000 milliseconds (60 seconds)
MAX_FAILED_ATTEMPTS="3"  # Maximum allowed failed login attempts

# Backup the settings.xml before modifying
cp "$SETTINGS_FILE" "${SETTINGS_FILE}.bak"
echo "Backup of settings.xml created at ${SETTINGS_FILE}.bak"

# Modify the ban duration (This is fine)
sed -i.bak -E "s|<ban_duration>[0-9]+</ban_duration>|<ban_duration>$BAN_DURATION</ban_duration>|" "$SETTINGS_FILE"

# Modify the first occurrence of login_failure_time_window (time window duration)
# Targets the first match globally (uses the '1' flag)
sed -i.bak -E 's|<login_failure_time_window>[0-9]+</login_failure_time_window>|<login_failure_time_window>'"$LOGIN_FAILURE_TIME_WINDOW"'</login_failure_time_window>|1' "$SETTINGS_FILE"

# Modify the second occurrence of login_failure_time_window (max allowed attempts)
# Targets the second match globally (uses the '2' flag)
sed -i.bak -E 's|<login_failure_time_window>[0-9]+</login_failure_time_window>|<login_failure_time_window>'"$MAX_FAILED_ATTEMPTS"'</login_failure_time_window>|2' "$SETTINGS_FILE"

echo "File $SETTINGS_FILE has been updated."
