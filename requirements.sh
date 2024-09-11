#!/bin/bash

# Check if pip is installed
if ! command -v pip &> /dev/null
then
    python3 -m ensurepip
fi

# Install cryptography module using pip and suppress details

pip install cryptography > /dev/null 2>&1

