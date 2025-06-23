#!/bin/bash

RNP_NIC_ROOT=$(dirname $(dirname $(readlink -f "$0")))

echo $RNP_NIC_ROOT

cd $RNP_NIC_ROOT/src
sudo make auxiliary_uninstall
make clean
make -j8
sudo make auxiliary_install
cd -
