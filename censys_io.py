#!/usr/bin/python2

import sys
import os
import json
import requests
import random
import glob
import nmap

from datetime import date
from argparse import ArgumentParser

CENSYS_API_ADDR = 'https://www.censys.io/api/v1/'
CENSYS_API_ID = 'fe857b4f-99d5-4239-955a-90bd65ba75bc'
CENSYS_API_SECRET = 'A95Maw51wALQVGTJmtGSmMcTUraAxebV'

class CensysHelp:

    def __init__(self, helpstr):

        self.helpstr = helpstr
        self.parselen = len(self.helpstr)
        try:
            runcmd = getattr(self,self.helpstr)
            runcmd()

        except AttributeError, err:
            print "Help for {} is not available.".format(self.helpstr)

    def search(self):
        print """
Usage: search [index] [query]
E.X. : search websites domain.com

About: Query for specific index data
       from the search endpoint.
        """

    def view(self):
        print """
Usage: view [index] [query]
E.X. : view ipv4 000.000.000.000

About: Query for specific index data
       from the view endpoint.
        """

    def query(self):
        print """
Usage: query [sql_query]
E.X. : query 'SELECT X FROM Y'

About: Execute raw SQL queries for
       data from the query endpoint.
       Only researchers verified through
       Censys IO have permission to use
       this endpoint.
        """

class CensysNmap:

    def __init__(self, keys):

        self.keys = keys
        self.pscanner = nmap.PortScanner()

    def service_scan(self):

        pass

class CensysAPI:

    def __init__(self, cmdstr):

        self.apicmd = cmdstr
        self.parselen = len(self.apicmd)
        try:
            runcmd = getattr(self,self.apicmd[0])
            runcmd()

        except AttributeError, err:
            print "Command not found."

    def search(self):
        '''Execute query against search endpoint
           using specific index type'''
        indexes = ['websites','ipv4','certificates']
        if self.parselen == 3:
            if self.apicmd[1] in indexes:
                search_url = CENSYS_API_ADDR + self.apicmd[0] + '/' + self.apicmd[1]
                search_obj = requests.post(search_url,
                                           auth=(CENSYS_API_ID,CENSYS_API_SECRET),
                                           data=json.dumps({'query':self.apicmd[2]}))
                searchjson = search_obj.json()
                check_res = is_censys_error(searchjson)
                if check_res:
                    print searchjson['error']

                else:
                    results = searchjson['results']
                    for hostdata in results:
                        ip = hostdata['ip']
                        print ip
                        proto = hostdata['protocols']
                        for p in proto:
                            print '   -{}'.format(p)

    def view(self):
        '''Execute query against view endpoint
           using specific index type'''
        indexes = ['websites','ipv4','certificates']
        if self.parselen == 3:
            if self.apicmd[1] in indexes:
                view_url = CENSYS_API_ADDR + self.apicmd[0] + '/' + self.apicmd[1] + '/' + self.apicmd[2]
                print view_url
                view_obj = requests.get(view_url, auth=(CENSYS_API_ID,CENSYS_API_SECRET))
                viewjson = view_obj.json()
                print viewjson.keys()

    def query(self):
        '''Execute SQL query against query endpoint'''
        if self.parselen >= 2:
            query_url = CENSYS_API_ADDR + self.apicmd[0]
            query_obj = requests.post(query_url, auth=(CENSYS_API_ID,CENSYS_API_SECRET), data=json.dumps({'query':self.apicmd[1]}))
            queryjson = query_obj.json()
            check_res = is_censys_error(queryjson)
            if check_res:
                print queryjson['error']

            else:
                print queryjson

    def help(self):
        '''Run help command to display general
           help or specific command help'''
        if self.parselen == 1:
            censys_help()

        elif self.parselen == 2:
            CensysHelp(self.apicmd[1])

        else:
            pass

    def exit(self):
        '''Exit Censys IO'''
        print "Thank you for using Censys IO."
        sys.exit()

class ConsoleAPI:

    def __init__(self,cmdstr):
        self.apicmd = cmdstr
        self.parselen = len(self.apicmd)
        try:
            runcmd = getattr(self,self.apicmd[0])
            runcmd()

        except AttributeError, err:
            print "Command not found."

    def hosts(self):
        pass

    def ports(self):
        pass

    def websites(self):
        pass

    def protos(self):
        pass

    def certs(self):
        pass

    def tags(self):
        pass

def censys_help():
    '''Censys full help menu. Todo
       includes integration into CensysHelp
       class.'''
    print '''
Censys API Commands
------------------------
search
view
query

Censys Console Commands
------------------------
hosts
ports
websites
protos
certs
tags
help
exit
    '''

def is_censys_error(json_obj):
    '''Checks JSON response from
       API endpoint.'''
    if json_obj['status'] == 'error':
        return True

    else:
        return False

def unpack_list(jl):
    '''function to unpack values from list. If values are a dict,
       send them back to unpack_json_keys()'''
    for obj in jl:
        if isinstance(obj, dict):
            unpack_json_keys(obj)
        else:
            print "   -{}".format(obj)

def unpack_json_keys(jres):
    '''function to unpack values from JSON dict. If values are a list,
       send them to unpack_list'''

    for k,v in jres.iteritems():
        if isinstance(v, dict):
            unpack_json_keys(v)

        elif isinstance(v, list):
            print k.upper()
            unpack_list(v)

        else:
            print '{}: {}'.format(k.upper(),v)
    print ''

def sort_ips(iplist):
    '''Sorts a list of IPv4 addresses'''
    return sorted(iplist, key=lambda ip: long(''.join(["%02X" % long(i) for i in ip.split('.')]), 16))

def sort_ports(portlist):
    '''Sorts a list of port numbers'''
    return map(str,sorted(map(int,portlist)))

def json_writer(jdata,jfile):
    '''Function to write JSON data
       to console session file.'''
    with open(jfile, 'w') as sfile:
        json.dump(jdata, sfile)
    return

def json_loader(jfile):

    with open(jfile, 'r') as jdata:
        sdata = json.load(jdata)
        return sdata

def new_keys():
    '''Creates new JSON key blob for
       console session.'''
    keys = {'censys_io':{'hosts':{'ports':{}}}}
    return keys

def create_session(sfile):

    skeys = new_keys()
    json_writer(skeys, sfile)
    print "Censys IO console session created."


def api_method(endpoint):

    methods = CENSYS_KEYS['endpoints'].keys()
    for m in methods:
        if endpoint in CENSYS_KEYS['endpoints'][m].keys():
            return m

def session_handler():
    console_sessions = '{}/.sessions/'.format(os.getcwd())
    current_session = 'censys-io-{}.session'.format(date.today())
    checkfile = glob.glob('{}/{}'.format(console_sessions,current_session))
    if len(checkfile) == 0:
        print "Console session not found: {}".format(current_session)
        create_session(current_session)
        loadkeys = json_loader(current_session)
        return loadkeys

    else:
        print "Using console session: {}".format(current_session)
        loadkeys = json_loader(current_session)
        return loadkeys

def censys_shell():
    session_handler()
    prompt = '#censys_io ~> '
    while True:
        cmd = raw_input(prompt)
        CensysAPI(cmd.split())

def banner():

    banner_path = '{}/banners/'.format(os.getcwd())
    random_banner = random.choice(glob.glob('{}*'.format(banner_path)))
    with open(random_banner,'r') as banner:
        print banner.read()

def main():
    os.system('clear')
    banner()
    censys_shell()

if __name__ == '__main__':
    main()
