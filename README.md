# CSE545_PCTF_PROJECT


## [Flag Submission](flag-submit)

This tool automatically submit flag for team. Provide either individual flag or file which stores multiple flags for submission. Change the `TEAM_INTERFACE_IP` and 
`TEAM_FLAG_TOKEN` variables according to team's information before running the script.

```
Usage:

  -s: submit individual flag
  
  -b: specify file which contains multiple flags
  
  -v: view information about our Virtual Machine in PCTF
 ```

Note: run command below to install setuptools on pctf vm before install libraries in requirements.txt

    pip install -U pip setuptools


## FAQS

1. Copy file/folder from local to host

    File: 

        scp -i key_file file_dir ctf@xxx.xxx.xxx.xxx:/home/ctf

    Folder: 

        scp -i key_file -r folder_dir ctf@xxx.xxx.xxx.xxx:/home/ctf

