#!/bin/bash

# Run the requirements.sh script
echo "Installing PortScanner"
bash requirements.sh

# Check if requirements.sh was successful
if [ $? -ne 0 ]; then
    echo "Failed to run PortScanner. Exiting."
    exit 1
fi

# Run the voldemort.py script
echo "Running PortScanner.py..."
python3 PortScanner.py

# Check if voldemort.py was successful
if [ $? -ne 0 ]; then
    echo "Failed to run PortScanner.py. Exiting."
    exit 1
fi

echo "PortScanner Installed Successfully."

