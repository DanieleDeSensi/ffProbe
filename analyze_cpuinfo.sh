#!/bin/sh
NUM_CHIPS=$(cat /proc/cpuinfo | grep 'physical id' | sort -u | wc -l)
FIRST_PROC_ID=$(cat /proc/cpuinfo | grep 'processor' | cut -d':' -f 2 | cut -d ' ' -f 2 | head -n 1)
PHY=$(cat /proc/cpuinfo | grep 'physical id' | cut -d':' -f 2 | cut -d ' ' -f 2)
CORE_ID=$(cat /proc/cpuinfo | grep 'core id' | cut -d':' -f 2 | cut -d ' ' -f 2)

rm tmpcpuinfo
echo $NUM_CHIPS >> tmpcpuinfo
echo $FIRST_PROC_ID >> tmpcpuinfo
echo $PHY >> tmpcpuinfo
echo $CORE_ID >> tmpcpuinfo
