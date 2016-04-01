#!/bin/sh
killall memcheck-amd64-
killall -9 tms
ipcrm -S 0x0000257b -M 0x0000257b
