# urlScan2Hive

Submits URLs to urlscan.io API by specifying `-u` option. Creates case in TheHive, then adds observables for tracking and intel sharing. 

# Usage
```
$ ./urlScan.py -h
usage: urlScan.py [-h] -u URL

optional arguments:
  -h, --help         show this help message and exit
  -u URL, --url URL  Suspect URL
  ```


# Example
```
captain@sift -> /m/h/D/b/urlscan 
$ ./urlScan.py -u http://pwned.site/victim.com/victim/officeee/index.html
============================
urlScan IOC generator,  1.1
============================
Username: responder
Password: 

[*] Submission successful
[*] Locating case template for suspected phishing
[*] Creating case from template
[*] Added URL observable for http://pwned.site/victim.com/victim/officeee/index.html
[*] Added IP observable for 173.185.165.90
[*] Added IP observable for 119.111.246.153
[*] Added domain observable for pwned.site
[*] Updated case with link to scan summary
[*] Updated case with screenshot found by following suspect URL

Case: https://hive.site.com:9443/index.html#/case/DWFwo00oLipxR_cNfMv1/details
```
# Requirements
```
Requires TheHive4py, Requests, and a urlscan.io API token. 
https://pypi.python.org/pypi/thehive4py/1.4.2
https://pypi.python.org/pypi/requests
https://urlscan.io/about-api/
```
