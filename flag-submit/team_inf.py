#!/usr/bin/env python3

# install package if need
# pip3 install swpag-client
# pip3 install argparse

import swpag_client
import argparse

TEAM_INTERFACE_IP = "127.0.0.1" # change when game start
TEAM_FLAG_TOKEN = "abcdef" # change when game start

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--individual-submit', help = 'Individual flag value for submit')
    parser.add_argument('-b', '--bulk-submit', help = 'File stored flags for submit')
    parser.add_argument('-v', '--view-team-info', help = 'View our team information', action='store_true')
    
    args = parser.parse_args()
    if not args.individual_submit and not args.bulk_submit and not args.view_team_info:
        parser.error("[-] Please specify one of methods to use --help for more info.")
    return args

def individual_submit(flag_value: str):
    """
    Submit individual flag
    """
    team_inf = swpag_client.Team(f"http://{TEAM_INTERFACE_IP}", TEAM_FLAG_TOKEN)
    try:
        res = team_inf.submit_flag([flag_value])
        print(res)
    except Exception as e:
        print(e)
    
def bulk_submit(store_file: str):
    """
    Submit flags stored in file
    """
    team_inf = swpag_client.Team(f"http://{TEAM_INTERFACE_IP}", TEAM_FLAG_TOKEN)
    
    try:
        with open(store_file, "r") as f:
            flags = [flag.strip() for flag in f.readlines()]
        
        res = team_inf.submit_flag(flags)
        print(res)
    except Exception as e:
        print(e)
        
def view_team_info():
    team_inf = swpag_client.Team(f"http://{TEAM_INTERFACE_IP}", TEAM_FLAG_TOKEN)
    try:
        res = team_inf.get_vm()
        print(res)
    except Exception as e:
        print(e)

if __name__ == "__main__":
    args = get_argument()
    
    if args.individual_submit:
        individual_submit(args.individual_submit)
        
    if args.bulk_submit:
        bulk_submit(args.bulk_submit)
    
    if args.view_team_info:
        view_team_info()    