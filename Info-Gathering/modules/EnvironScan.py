#!/usr/bin/env python3
"""
EnvironScan.py
Author: William Walker
Purpose: Collect environment var artifacts from a compromised Linux box.

This module collects: Current process environment variables (os.environ)

Can be run by itself or imported by FullInfoScan.py
"""

import os
import json


"""
Collect current environment variables.
Returns a dict of key and value pairs.
"""
def collect_environ():

    try:
        return dict(os.environ)
    except Exception:
        return None


"""
Main function used by FullInfoScan.py
Returns a dict of environment var data.
"""
def run():

    data = {
        "environment_variables": collect_environ()
    }

    return data


"""
Prints results to terminal.
"""
def alone():
    data = run()
    print(json.dumps(data, indent=4))


if __name__ == "__main__":
    alone()