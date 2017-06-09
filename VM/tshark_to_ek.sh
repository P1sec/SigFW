#!/bin/bash -
tshark -i enp0s9 -T ek -l | /opt/SigFW/VM/line_curl.sh
