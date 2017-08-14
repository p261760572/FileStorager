#!/bin/sh
killall memcheck-amd64-
killall -9 FileStorager
ipcrm -S 0x0000257d -M 0x0000257d
