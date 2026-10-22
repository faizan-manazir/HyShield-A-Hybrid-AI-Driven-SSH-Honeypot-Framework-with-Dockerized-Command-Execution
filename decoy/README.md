# HyShield decoy filesystem seed

This script creates a small, fictional Ubuntu web-server filesystem inside the
fake-ubuntu container. All names, log records, and credential-like values are
synthetic. It does not start services or provide real authentication.

## Preview the changes

Run the tests from the repository root:

    python3 -m unittest discover -s tests -p 'test_decoy_seed.py' -v

## Apply inside the container

First ensure fake-ubuntu is the disposable decoy container, not a production
container. Copy the script into it and run it there:

    docker cp decoy/seed_decoy_filesystem.py fake-ubuntu:/tmp/seed_decoy_filesystem.py
    docker exec fake-ubuntu python3 /tmp/seed_decoy_filesystem.py --root /

The script creates only missing files and leaves existing files untouched on
subsequent runs. Review the container filesystem before applying it if the
container already contains data. It is not safe to run with --root / on the
host OS; the documented command runs it inside the named container.

## Scope and limitations

The profile is a web-server decoy, not a complete emulation of Ubuntu or a
running web stack. Some files refer to services that may not be installed or
running. Before public exposure, align the decoy's installed packages, service
state, hostname, users, permissions, and logs; test command consistency and
session isolation. Do not mount sensitive host paths or the Docker socket into
the container. Use resource limits and restricted network egress.
