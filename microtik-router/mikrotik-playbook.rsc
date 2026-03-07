# MikroTik Playbook - NCAE CyberGames

# IPs & Routing
/ip address add address=172.18.13.1/16 interface=ether1
/ip address add address=192.168.1.1/24 interface=ether2
/ip route add gateway=172.18.0.254
/ip dns set servers=8.8.8.8 allow-remote-requests=yes
/ip firewall nat add chain=srcnat out-interface=ether1 action=masquerade

# Firewall - Input
/ip firewall filter
add chain=input connection-state=established,related action=accept
add chain=input connection-state=invalid action=drop
add chain=input protocol=icmp action=accept
add chain=input in-interface=ether2 action=accept
add chain=input protocol=tcp dst-port=22 in-interface=ether1 action=accept
add chain=input action=drop

# Firewall - Forward
add chain=forward connection-state=established,related action=accept
add chain=forward connection-state=invalid action=drop
add chain=forward in-interface=ether2 action=accept
add chain=forward in-interface=ether1 dst-address=192.168.1.5 protocol=tcp dst-port=80,443 action=accept
add chain=forward in-interface=ether1 dst-address=192.168.1.12 protocol=tcp dst-port=53 action=accept
add chain=forward in-interface=ether1 dst-address=192.168.1.12 protocol=udp dst-port=53 action=accept
add chain=forward in-interface=ether1 dst-address=192.168.1.7 protocol=tcp dst-port=5432 action=accept
add chain=forward in-interface=ether1 protocol=icmp action=accept
add chain=forward in-interface=ether1 action=drop

# Harden
/user set admin password=CyberRouter2026!
/ip service set telnet disabled=yes
/ip service set ftp disabled=yes
/ip service set www disabled=yes
/ip service set api disabled=yes
/ip service set api-ssl disabled=yes
/ip service set winbox disabled=yes
/ip service set ssh address=172.18.0.0/16,192.168.1.0/24
/tool bandwidth-server set enabled=no
/tool mac-server set allowed-interface-list=none
/tool mac-server mac-winbox set allowed-interface-list=none
/tool mac-server ping set enabled=no
/ip neighbor discovery-settings set discover-interface-list=none
/ip socks set enabled=no
/ip upnp set enabled=no
/system ntp client set enabled=yes servers=pool.ntp.org
