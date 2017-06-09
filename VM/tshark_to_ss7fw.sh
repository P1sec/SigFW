#!/bin/bash -
tshark -i enp0s9 -T ek -x -j " " -l > /opt/SigFW/ss7fw/ss7fw.ss7fw-core_jar_1.0.0-SNAPSHOT/input/pipe
