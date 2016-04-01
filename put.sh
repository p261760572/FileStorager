#!/bin/sh
sftp tlapp@10.80.1.187 <<EOF
cd /home/tlapp/bin
put tlapp
exit
EOF
