#!/bin/bash

poetry build
# Copy content of dist folder to ~/V2G/bin/V2GEvil/
cp ~/V2G/repos/V2GEvil/dist/* ~/V2G/bin/V2GEvil/
sudo pip3 install ~/V2G/bin/V2GEvil/*.whl
sudo v2gevil --help
