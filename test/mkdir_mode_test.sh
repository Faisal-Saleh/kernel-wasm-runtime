#!/bin/bash

make

# load the kernel module
echo "Loading kernel module..."
sudo insmod kernel_wasm.ko

if [ $? -ne 0 ]; then
  echo "Failed to load kernel module."
  exit 1
fi

# create directories to observe the report output
echo "Creating directories for observing report output..."
mkdir -p /tmp/wasm_reports

# load the WASM binary
echo "Loading WASM binary..."
sudo ./wasm_manager load wasm_probes/mkdir_mode.wasm

sudo ./wasm_manager list

mkdir -p /tmp/wasm_test
sudo ./wasm_manager report 1 > /tmp/wasm_reports/report_output.log
actual_output=$(tail -n 1 /tmp/wasm_reports/report_output.log)
expected_output="Report: The mode of the directory created is 511"

if [[ "$actual_output" == "$expected_output" ]]; then
    echo "Test Passed!"
else
    echo "Test Failed!"
    echo "Expected: $expected_output"
    echo "Actual: $actual_output"
    exit 1
fi

# clean up
echo "Cleaning up..."
sudo rmmod kernel_wasm
rm -rf /tmp/wasm_reports
rm -rf /tmp/wasm_test