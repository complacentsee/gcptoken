#!/bin/bash
cp -R -v /workspace /opt
/opt/cmd.sh
ls -l /opt/workspace/build/
cp /opt/workspace/build/firmware.bin /workspace/firmware.bin