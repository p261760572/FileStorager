#!/bin/sh
sftp tms@10.80.1.178 <<EOF
cd /home/tms/bin
put tms
exit
EOF
