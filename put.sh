#!/bin/sh
sftp tms@10.80.1.187 <<EOF
cd /home/tms/bin
put tms
exit
EOF
