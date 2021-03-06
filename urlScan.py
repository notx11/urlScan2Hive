#!/usr/bin/env python3

import argparse
import json
import getpass
import requests
import time
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseObservable

__author__ = "Wayland Morgan"
__description__ = "Submits a suspect URL for analysis and adds resulting observables to TheHive"

def submit_to_urlscan(surl):
    url = 'https://urlscan.io/api/v1/scan/'
    headers = {'Content-Type': 'application/json', 'API-Key': 'YOUR-API-KEY'}
    data = """{\"url\": \"%s\", \"public\": \"on\"}""" % (surl)
    response = requests.post(url, data=data, headers=headers)
    response.raise_for_status()
    return response
    
def main(): 
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Suspect URL")
    args = parser.parse_args()
    surl = args.url
        
    user = input("Username: ")
    password = getpass.getpass()
    thehive = TheHiveApi('https://127.0.0.1:9443', user, password, {'http': '', 'https': ''})
    
    # Submit URL for processing
    response = submit_to_urlscan(surl)
    receipt = json.loads(response.content)
    uuid = receipt['uuid']
    
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
    case = Case(title='Email Campaign', description='N/A', tlp=2, template='Email - Suspect Phishing', tags=['email'])
    
    # Create the case
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
    
    case.description = '[Scan Summary](https://urlscan.io/results/{0}/#summary)\n\n'.format(uuid)
    case.description += screenshot + "\n\n"
    
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
 
    case.id = id
    thehive.update_case(case, ['description'])
    print('\nCase: ' + 'https://127.0.0.1:9443/index.html#/case/{0}/details'.format(id))

if __name__ == '__main__':
    main()
