#!/usr/bin/env python

import argparse
import json
import getpass
import requests
import time
import httplib as http_client
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseObservable

__author__ = "Wayland Morgan"
__date__ = "20180125"
__version__ = "1.2"
__description__ = "Submits a suspect URL for analysis and adds resulting observables to TheHive"

def submit_to_urlscan(surl):
    url = 'https://urlscan.io/api/v1/scan/'
    headers = {'Content-Type': 'application/json', 'API-Key': 'YOUR-API-KEY'}
    data = """{\"url\": \"%s\", \"public\": \"on\"}""" % (surl)
    response = requests.post(url, data=data, headers=headers)
    response.raise_for_status()
    return response
    
def debug_api():
    http_client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True
    
def main(): 
    # Submit URL for processing
    response = submit_to_urlscan(surl)
    receipt = json.loads(response.content)
    uuid = receipt['uuid']
    print '\n[*] ' + receipt['message']
    
    # Wait for scan to finish then retrieve results
    time.sleep(15)
    response = requests.get('https://urlscan.io/api/v1/result/{}/'.format(uuid))
    results = json.loads(response.content)
    
    # Parse response and assign variables
    screenshot = '![{0}](https://urlscan.io/thumbs/{1}.png)'.format(surl, uuid)
    ipaddrs = results['lists']['ips']
    domains = results['lists']['domains']
    
    try:
        certificates = results['lists']['certificates']
    except KeyError:
        pass    

    try: 
        threatDict = results['meta']['processors']['gsb']['data']['matches'][0]
        safebrowse = threatDict.get("threatType").lower()
    except KeyError:
        safebrowse = "nullSafeBrowseTag"
        
    urls = set()
    for i in results['data']['requests']:
        for k, v in i.iteritems():
            if k == "request":
                urls.add(v.get("documentURL"))
                
    # Locate template
    print '[*] Locating case template for suspected phishing'
    case = Case(title='Email Campaign', description='N/A', tlp=2, template='Email - Suspect Phishing', tags=['email'])
    
    # Create the case
    print '[*] Creating case from template'
    response = thehive.create_case(case)
    id = response.json()['id']
    
    # Add captured values as observables
    '\n'.join(urls)
    for i in urls:
        urlv = CaseObservable(dataType='url',
                              data=i,
                              tlp=1,
                              ioc=False,
                              tags=['thehive4py', 'url', 'phishing'],
                              message='from urlscan.io'
                              )
        urlv.tags.append(safebrowse)
        response = thehive.create_case_observable(id, urlv)
        if response.status_code == 201:
            print '[*] Added URL observable for ' + i
        else:
            print '[!] ko: {}/{}\n'.format(response.status_code, response.text)

    for i in domains:
        domainv = CaseObservable(dataType='domain',
                                data=i,
                                tlp=1,
                                ioc=False,
                                tags=['thehive4py', 'domain', 'phishing'],
                                message='from urlscan.io'
                                )
        domainv.tags.append(safebrowse)
        response = thehive.create_case_observable(id, domainv)
        if response.status_code == 201:
            print '[*] Added domain observable for ' + i
        else:
            print '[!] ko: {}/{}\n'.format(response.status_code, response.text)
    
    case.description = '[Scan Summary](https://urlscan.io/results/{0}/#summary)\n\n'.format(uuid)
    print '[*] Updated case with link to scan summary'
    case.description += screenshot + "\n\n"
    print '[*] Updated case with screenshot found by following suspect URL'
    
    if certificates:
        for k, v in certificates[0].iteritems():
            if k == "subjectName":
                case.description += "```\nSubject Name: " + v + "\n"
            if k == "validFrom": 
                case.description += "Valid from: " + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(v)) + "\n"
            if k == "validTo":
                case.description += "Valid to: " + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(v)) + "\n"
            if k == "sanList":
                s = ', '.join(v)
                case.description += "San list: " + s + "\n"
            if k == "issuer":
                case.description += "Issuer: " + v + "\n```"
        print '[*] Added certificate information to case'
 
    case.id = id
    thehive.update_case(case, ['description'])
    print '\nCase: ' + 'https://127.0.0.1:9443/index.html#/case/{0}/details'.format(id)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Debug API call")
    parser.add_argument("-u", "--url", required=True, help="Suspect URL")
    args = parser.parse_args()
    surl = args.url
 
    if args.debug:
        debug_api()
        
    print '{:=^28}'.format('')
    print '{} {}'.format('urlScan IOC generator, ', __version__)
    print '{:=^28}'.format('')
    user = raw_input("Username: ")
    password = getpass.getpass()
    thehive = TheHiveApi('https://127.0.0.1:9443', user, password, {'http': '', 'https': ''})
    main()
