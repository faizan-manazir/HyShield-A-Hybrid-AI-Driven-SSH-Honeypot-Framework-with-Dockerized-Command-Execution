#!/bin/bash

# Set PYTHONPATH
export PYTHONPATH=/home/faizan/cowrie/src

# Randomly pick one password before starting
python3 /home/faizan/cowrie/update_password.py

# Save active password
awk -F: '{print $3}' /home/faizan/cowrie/etc/userdb.txt | tr -d '[:space:]' > /home/faizan/cowrie/active_password.txt

# Show active password
echo "Active password: $(cat /home/faizan/cowrie/active_password.txt)"

# Activate venv and start Cowrie
source /home/faizan/cowrie/cowrie-env/bin/activate
cd /home/faizan/cowrie
twistd -n cowrie

docker start fake-ubuntu

python3 bridge_server.py
