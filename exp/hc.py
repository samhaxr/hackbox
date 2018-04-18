
import httplib
import sys
from colorama import *
version = "1"

def usage():
    print ""
    
if len(sys.argv) < 3:
    usage()
    sys.exit()

host = sys.argv[1]
conn = httplib.HTTPConnection(host)
dir = sys.argv[2]
conn.request("GET", dir)
response = conn.getresponse()
data = response.read()



headers = {"X-XSS-Protection":['1; mode=block'], 
    "X-Content-Type-Options":['nosniff'],
    "X-Frame-Options":['DENY','SAMEORIGIN'],
    "Cache-Control":['no-store, no-cache','no-cache, no-store'],
    "Content-Security-Policy":[None],
    "WebKit-X-CSP":[None],
    "X-Content-Security-Policy":[None],
    "Strict-Transport-Security":[None],
    "Access-Control-Allow-Origin":[None],
    "Origin":[]}




def passed(bar):
    print "PASS = ", bar
    
def failed(bar):
    print "FAIL = ", bar

def info(host):
    print "-----------------------------------"
    print "Target - ", host
    print "-----------------------------------"
    




       
info(host)

for h in headers.keys():
    headval = response.getheader(h)
    if headval in headers[h]:
        if headers[h] == "Origin":
            if headval != None:
                failed(h+': '+str(headval))
            else:
                passed(h+': '+str(headval))
        passed(h+': '+str(headval))        
    else:
        failed(h+': '+str(headval))
