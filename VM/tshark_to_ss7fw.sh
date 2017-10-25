#!/bin/bash -
tshark -i enp0s9 -T ek -x -j " " -l > /opt/SigFW/sigfw/sigfw.sigfw/input/pipe
