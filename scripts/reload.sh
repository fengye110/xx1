#!/bin/bash

MCE_NIC_ROOT=$(dirname $(dirname $(readlink -f "$0")))

echo $MCE_NIC_ROOT

sudo rmmod mcepf
sudo rmmod mucse_auxiliary

sudo insmod $MCE_NIC_ROOT/src/mucse_auxiliary.ko
sudo insmod $MCE_NIC_ROOT/src/mcepf.ko
