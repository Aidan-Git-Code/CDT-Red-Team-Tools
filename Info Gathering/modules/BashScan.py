#!/usr/bin/env python3
"""
BashScan.py
Author: William Walker
Purpose: Collect shell history artifacts from a compromised Linux box.

This module collects: ~/.bash_history ~/.zsh_history /root/.bash_history (if readable) /root/.zsh_history (if readable)

Can be run by itself or imported by FullInfoScan.py
"""

import os
import json

try:
    from .utils import read_file, get_user_home
except ImportError:
    from utils import read_file, get_user_home


"""
Collect shell history files for the curr user.
"""
def collect_user_history():
    
    home = get_user_home()
    if not home:
        return None

    history_raw = read_file(os.path.join(home, ".bash_history"))
    history_list = history_raw.splitlines() if isinstance(history_raw, str) else history_raw

    return {
    "bash_history": history_list
    }



"""
Main function used by FullInfoScan.py
Returns a dict of shell history data.
"""
def run():

    data = {
        "user_history": collect_user_history(),
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