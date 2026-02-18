#!/usr/bin/env python3
"""
utils.py
Author: William Walker
Purpose: Shared helper functions for multiple scan modules.
"""

import os



"""
Reads a file and returns its contents, or a clear message if missing/unreadable.
"""
def read_file(path):
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                return f.read()
        else:
            return "does not exist"
    except Exception:
        return "unreadable"
    

"""
Return the path to the current user's home directory.
"""
def get_user_home():
    try:
        return os.path.expanduser("~")
    except Exception:
        return None
