#!/bin/bash

set +e

cargo build

mkdir -p output

sudo install -v -d -m755 /run/systemd/system
cat << EOF | sudo tee /run/systemd/system/opoj-42.slice > /dev/null
[Unit]
Requires=opoj-empty-ns@42.service

[Slice]
CPUQuota=100%
AllowedCPUs=0
TasksMax=32
EOF

sudo cp ../etc/systemd/system/opoj-empty-ns@.service /run/systemd/system/

sudo systemctl daemon-reload

sudo systemctl stop opoj-42.slice
sudo systemctl stop opoj-empty-ns@42.service

for i in {1..19}; do
	sudo ../target/debug/judge-client-3 test$i 42 .
done

sudo chmod 666 output/*
