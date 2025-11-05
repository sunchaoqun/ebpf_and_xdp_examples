#!/bin/bash

# XDP Connection Limiter Runner Script

INTERFACE=${1:-ens3}

echo "Starting XDP Connection Limiter on interface: $INTERFACE"
echo "Target Port: 9015, Max Connections: 200"
echo ""

# Run the program
sudo ./main $INTERFACE

# Cleanup on exit
echo "Cleaning up..."
sudo ip link set dev $INTERFACE xdpgeneric off 2>/dev/null

