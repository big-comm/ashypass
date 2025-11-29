#!/bin/bash
# Ashy Pass Launcher Script

# Change to application directory
cd "$(dirname "$0")"

# Run the application
python3 main.py "$@"
