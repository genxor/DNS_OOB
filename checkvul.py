#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
author genxor

普通查询
http://IP:8181/_query
检测API:
http://IP:8181/_check?type=dns&uuid=xxx
http://IP:8181/_allincheck?type=dns&uuid=xxx
回显API
http://IP:8181/_echo?type=dns&uuid=xxx
"""

import os
import re
import socket
import threading
import base64
import BaseHTTPServer
import time
import json
import urlparse

#specify ip to  reserved  domins  
resolveconfig={'www.xdebug.info':"114.114.114.114", "xdebug.info":"127.0.0.1"}
dnsname = 'xdebug.info'
prefix = 'check'
argsname = ['type', 'uuid']
blacklist=["NS1.XDEBUG.INFO", "NS2.XDEBUG.INFO"]

class DNSQuery(object):
    """
    Used for making fake DNS resolution responses based on received
    raw request

    Reference(s):
        http://code.activestate.com/recipes/491264-mini-fake-dns-server/
        https://code.google.com/p/marlon-tools/source/browse/tools/dnsproxy/dnsproxy.py
    """

    def __init__(self, raw, addr):
        self._raw = raw
        self._query = ""
        self._ip = addr[0]
        self._src_port= addr[1]

        type_ = (ord(raw[2]) >> 3) & 15                 # Opcode bits

        if type_ == 0:                                  # Standard query
            i = 12
            j = ord(raw[i])

            while j != 0:
                self._query += raw[i + 1:i + j + 1] + '.'
                i = i + j + 1
                j = ord(raw[i])

    def response(self, resolution):
        """
        Crafts raw DNS resolution response packet
        """

        retVal = ""

        if self._query:
            retVal += self._raw[:2]                                             # Transaction ID
            retVal += "\x85\x80"                                                # Flags (Standard query response, No error)
            retVal += self._raw[4:6] + self._raw[4:6] + "\x00\x00\x00\x00"      # Questions and Answers Counts
            retVal += self._raw[12:(12 + self._raw[12:].find("\x00") + 5)]      # Original Domain Name Query
            retVal += "\xc0\x0c"                                                # Pointer to domain name
            retVal += "\x00\x01"                                                # Type A
            retVal += "\x00\x01"                                                # Class IN
            retVal += "\x00\x00\x00\x20"                                        # TTL (32 seconds)
            retVal += "\x00\x04"                                                # Data length
            retVal += "".join(chr(int(_)) for _ in resolution.split('.'))       # 4 bytes of IP

        return retVal

class DNSServer(object):
    def __init__(self):
        #self._requests = []
        self._requests = {}
        self._lock = threading.Lock()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("", 53))
        self._running = False
        self._initialized = False

    def pop(self, prefix=None, suffix=None):
        """
        Returns received DNS resolution request (if any) that has given
        prefix/suffix combination (e.g. prefix.<query result>.suffix.domain)
        """

        retVal = None
        clientip = None

        with self._lock:
            for _ in self._requests.keys():
                if prefix is None and suffix is None or re.search("%s\..+\.%s" % (prefix, suffix), _, re.I):
                    retVal = _
                    clientip = self._requests[_]
                    del self._requests[_]
                    break

        return retVal, clientip

    def run(self):
        """
        Runs a DNSServer instance as a daemon thread (killed by program exit)
        """

        def _():
            try:
                self._running = True
                self._initialized = True

                while True:

                    try:
                        data, addr = self._socket.recvfrom(1024)
                        _ = DNSQuery(data, addr)
                        if _._query.strip(".") in resolveconfig.keys():
                            #ddns
                            self._socket.sendto(_.response(resolveconfig[_._query.strip(".")]), addr)
                        else:
                            self._socket.sendto(_.response("127.0.0.1"), addr)

                        with self._lock:
                            self._requests[_._query] = _._ip
                    except Exception,e:
                        print e
            except KeyboardInterrupt:
                raise

            finally:
                self._running = False

        thread = threading.Thread(target=_)
        thread.daemon = True
        thread.start()
    
    def doDiff(self, logs):
        global lastlogs, diff, difflogs
        tmp = list(set(logs).difference(set(lastlogs)))
        diff += tmp
        if not len(tmp) and len(diff):
            difflogs = diff[:]
            diff = []
        lastlogs = logs[:]
        return difflogs

def startweblistenner():
    class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        def is_base64_code(self, s):
            '''Check s is Base64.b64encode'''
            if not isinstance(s ,str) or not s:
                #raise ValueError, "params s not string or None"
                return False
        
            _base64_code = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
                            'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                            'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a',
                            'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
                            't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
                            '2', '3', '4','5', '6', '7', '8', '9', '+',
                            '/', '=' ]
        
            # Check base64 OR codeCheck % 4
            code_fail = [ i for i in s if i not in _base64_code]
            if code_fail or len(s) % 4 != 0:
                return False
            return True

        def vulcheck(self,logs, uuid):
            data = {}
            data['uuid'] = uuid
            if len(logs):
                sub = '.%s.%s' % (uuid, dnsname)
                for log in logs:
                    if sub in log:
                        data['log'] = log
                        data['result'] = 1
                        return json.dumps(data)
            data['log'] = ""
            data['result'] = 0
            return json.dumps(data)

        def allincheck(self,logs, uuid):
            data = {}
            data['uuid'] = uuid
            data['log'] = []
            data['pay'] = []
            data['result'] = 0
            if len(logs):
                sub = '.%s.%s' % (uuid, dnsname)
                for log in logs:
                    if sub in log:
                        data['log'].append(log)
                        data['pay'].append(log.split('.')[0])
                        data['result'] = 1
            return json.dumps(data)

        def vulEcho(self, logs, uuid):
            data = {}
            data['uuid'] = uuid
            if len(logs):
                data['log'] = logs[0]
                sub = '.%s.%s' % (uuid, dnsname)
                dns = {}
                str = ''
                for log in logs:
                    if sub in log:
                        domain = log.split('\t')[0]
                        b64 = domain.split('.')[0]
                        index = domain.split('.')[1]
                        dns[int(index)] = b64
                if len(dns):
                    for _ in sorted(dns.keys()):
                        str += dns[_]
                    if self.is_base64_code(str):
                        data['result'] = base64.b64decode(str)
                        return json.dumps(data)
                    else:
                        data['result'] = "Lost Data!!!"
                        return json.dumps(data)
            data['log'] = ''
            data['result'] = ''
            return json.dumps(data)

        def decrtpy(self, logs):
            dns = {}
            data = ''
            for i in logs:
                domain = i.split('\t')[0]
                if re.search("^[A-Za-z\d+/=]+\.\d+\.", domain, re.I):
                    b64 = domain.split('.')[0]
                    index = domain.split('.')[1]
                    dns[int(index)] = b64
            if len(dns):          
                for _ in sorted(dns.keys()):
                    data += dns[_]
                if self.is_base64_code(data):
                    return base64.b64decode(data)
                else:
                    return "Lost Data!!!"
            else:
                return ''
        
        '''
        nslookup check.uuid.etbrainsoft.com
        '''
        def do_GET(self):
            ip = self.client_address[0]
            global mutex,accesslog,querylogs, difflogs
            mutex.acquire()
            log = "%s\t%s\t%s" % (ip, self.path, time.strftime("%Y-%m-%d %H:%M:%S"))
            if log not in accesslog:
                accesslog.append(log)
            if len([accesslog]) > 100:
                accesslog = accesslog[-100:]
            mutex.release()
            if len([querylogs]) > 100:
                querylogs = querylogs[-100:]
                # mutex.release()

            parsed = urlparse.urlparse(self.path)
            self.send_response(200)
            if parsed.path == "/":
                self.send_header("Content-type", "application/xml")
                self.end_headers()
                self.wfile.write("<xml><a>eye</a></xml>")
            else:
                key = parsed.path[1:]
                qs = dict(urlparse.parse_qsl(parsed.query))  # parse get args
                if key == '_query':
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(r'<h1><a name="001" id="001">ECHO</a></h1>')
                    self.wfile.write("<br>"+self.decrtpy(difflogs).replace('\n', '<br>'))
                    self.wfile.write("<br/>" )
                    self.wfile.write("*"*100)
                    self.wfile.write("<br/>")
                    self.wfile.write(r'<h1><a name="002" id="002">DNS</a></h1>')
                    '''
                    self.wfile.write(str(len(querylogs))+"<br>")
                    self.wfile.write("<br>".join(reversed(querylogs)))
                    self.wfile.write("<br/>" )
                    #'''
                    #self.wfile.write(str(len(difflogs))+"<br>")
                    self.wfile.write("<br>".join(reversed(difflogs)))
                    self.wfile.write("<br/>" )
                    self.wfile.write("*"*100)
                    self.wfile.write('<h1><a name="003" id="003">weblog</a></h1>')
                    self.wfile.write("<br>".join(reversed(accesslog)))

                if key == '_check' and qs.keys() == argsname and len(qs['uuid']) == 12:
                    if qs['type'] == 'dns':
                        data = self.vulcheck(checklogs, qs['uuid'])
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(data)
                    if qs['type'] == 'http':
                        pass
                elif key == '_allincheck' and qs.keys() == argsname and len(qs['uuid']) == 12:
                    if qs['type'] == 'dns':
                        data = self.allincheck(allin, qs['uuid'])
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(data)
                    if qs['type'] == 'http':
                        pass
                elif key == '_echo' and qs.keys() == argsname and len(qs['uuid']) == 12:
                    if qs['type'] == 'dns':
                        data = self.vulEcho(echologs, qs['uuid'])
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(data)
                    if qs['type'] == 'http':
                        pass
                else:
                    self.send_header("Content-type", "application/xml")
                    self.end_headers()
                    self.wfile.write("<xml><a>eye</a></xml>")

    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class(("", 8181), MyHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    pass


def dostartweblistenner():
    thread = threading.Thread(target=startweblistenner)
    thread.daemon = True
    thread.start()

if __name__ == "__main__":
    global mutex, querylogs
    mutex = threading.Lock()

    checklogs = [] # 扫描器检查漏洞使用
    allin = [] # 扫描器检查漏洞使用
    echologs = [] # 扫描器打印回显结果使用
    querylogs = [] #日常所有日志

    #dodiff使用
    lastlogs = [] # dodiff对比取差异querylogs使用
    diff = [] # dodiff 中间结果
    difflogs = [] # 出现的差异

    #web日志
    accesslog = []

    #'''
    dostartweblistenner()
    server = None
    try:
        server = DNSServer()
        server.run()

        while not server._initialized:
            time.sleep(0.1)

        while server._running:
            while True:
                _, ip = server.pop()

                if _ is None:
                    break
                else:
                    #mutex.acquire()
                    if _.strip('.').upper() not in blacklist:
                        log = "%s\t%s\t%s"%(_, ip, time.strftime("%Y-%m-%d %H:%M:%S") )
                        if re.search("%s\.\w{12}\.%s" % (prefix, dnsname), log, re.I):
                            checklogs.append(log)
                        elif re.search("^[A-Za-z\d+/=]+\.\d+\.\w{12}\.%s" % dnsname, log, re.I):
                            echologs.append(log)
                        elif re.search("^\w+\.\w{12}\.%s" % dnsname, log, re.I):
                            allin.append(log)
                        elif log not in querylogs:
                            querylogs.append(log)

                        if len([querylogs])>500:
                            querylogs=querylogs[-500:]
                        #mutex.release()
                        print "%s" % log
            server.doDiff(querylogs)
            time.sleep(1)
    except socket.error, ex:
        if 'Permission' in str(ex):
            print "[x] Please run with sudo/Administrator privileges"
        else:
            raise
    except KeyboardInterrupt:
        os._exit(0)
    finally:
        if server:
            server._running = False
    #'''

