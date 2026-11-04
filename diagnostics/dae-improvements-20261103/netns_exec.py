#!/usr/bin/env python3
"""Prepare loopback inside an anonymous network namespace, then exec a test."""
import os
import subprocess
import sys

subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
os.execvp(sys.argv[1], sys.argv[1:])
