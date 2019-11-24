#!/bin/sh

sudo apt-get update && \
sudo apt-get -y install python3-pip && \
sudo pip3 install -r requirements.txt
ls -1 config.json || echo "ok"
mkdir output
