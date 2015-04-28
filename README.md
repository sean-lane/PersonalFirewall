# Personal Firewall

Build the module with "make"
Clean module (for new builds) with "make clean"

Load the module into kernel with "make load"
Unload the module from kernel with "make unload"

Use "dmesg" to see kernel info log.

Userspace Commands:

./userspace --print

./userspace --delete rule_id(ex. 1)

./userspace --new --ip ip_address --port port# --protocol protocol_type --action BLOCK/UNBLOCK

gcc -std=c99 -o userspace -userspace.c
