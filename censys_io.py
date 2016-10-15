#!/usr/bin/python2

import sys
import os
import json
import requests
import random
import glob

from datetime import date
from argparse import ArgumentParser

def load_api_keys():
    '''Reads the keys stored in .ec2_keys
       and returns them in a list'''
    with open('{}/.censys_api_keys'.format(os.getcwd()),'r') as ec2keys:
        return ec2keys.read()

CENSYS_API_ADDR = 'https://www.censys.io/api/v1/'
CENSYS_API_ID = sorted(load_api_keys().strip().split('\n'))[0].split('=')[1].strip()
CENSYS_API_SECRET = sorted(load_api_keys().strip().split('\n'))[1].split('=')[1].strip()

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

    def domains(self):

        print """
Usage: domains <domain>
E.X. : domains optionaldomain.com

About: Shows the current domains within
       the loaded console session. A domain
       name may be passed to this command as
       an additional argument to show metrics
       for specific domain names.
       """

    def hosts(self):


        print """
Usage: hosts <host>
E.X. : hosts 000.000.000.000
       hosts 000.000.000.000,000.000.000.007
       hosts 000.000.000.000/00
       hosts 000.000.000.000-000

About: Shows all current hosts per domain
       within the currently loaded console
       session. An IP address or list of IP
       addresses may be passed in multiple
       formats as an additional argument to
       show metrics for specific host addresses.
       """

    def ports(self):

        print """
Usage: ports <port>
E.X. : ports 21
       ports 22,23,3389
       ports 80-443

About: Shows all current port numbers loaded
       in the console session. A port number
       or list of port numbers may be passed
       as an additional argument to show metrics
       for specific port numbers per host.
       """

    def protos(self):

       print """
Usage: protos <proto>
E.X. : protos ftp
       protos ssh,telnet,rdp

About: Shows all current protocols loaded
       in the console session. A protocol
       name or list of protocol names may
       be passed as an additional argument
       to show metrics for specific protocol
       types.
        """

    def metrics(self):

        print """
Usage: metrics <type>
E.X. : metrics overview
       metrics details

About: Shows all current metrics for
       the currently loaded console
       session. An optional argument may be passed
       to view an overview of the current session's
       metrics or a detailed outline of the current
       session's metrics.
        """
    def exit(self):

        print """
Usage: exit

About: Exit Censys IO.
        """

class CensysAPI:

    def __init__(self, cmdstr, keys):

        self.apicmd = cmdstr
        self.keys = keys
        self.parselen = len(self.apicmd)
        try:
            runcmd = getattr(self,self.apicmd[0])
            runcmd(self.keys)

        except AttributeError, err:
            print "API command not found."
            print self.apicmd

    def search(self,keys):

        '''Execute query against search endpoint
           using specific index type'''
        indexes = ['websites','ipv4','certificates']
        tlds = ['com','net','org','edu','in','gov','io']
        print keys
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

                else: #NEED TO ADD LOGIC TO HANDLE WEBSITE AND CERTIFICATE DATA FOR PARSING AND SAVING SESSION DATA
                    if '.' in self.apicmd[2] and self.apicmd[2].split('.')[1].strip() in tlds:
                        if self.apicmd[2] not in keys['censys_io']['domains'].keys():
                            keys['censys_io']['domains'].update({self.apicmd[2]:{'hosts':{}}})
                            results = searchjson['results']
                            for hostdata in results:
                                ip = hostdata['ip']
                                if ip in keys['censys_io']['domains'][self.apicmd[2]]['hosts'].keys():
                                    continue
                                hostkeys = {}
                                proto = hostdata['protocols']
                                protolist = []
                                for p in proto:
                                    protolist.append(p)
                                hostkeys.update({'protos':protolist})
                                keys['censys_io']['domains'][self.apicmd[2]]['hosts'].update({ip:hostkeys})

                    else:
                        print searchjson

    def view(self,keys):

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

    def query(self,keys):

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

    def help(self,keys):

        '''Run help command to display general
           help or specific command help'''
        if self.parselen == 1:
            censys_help()

        elif self.parselen == 2:
            CensysHelp(self.apicmd[1])

        else:
            pass

class ConsoleAPI:

    def __init__(self,cmdstr,keys):

        self.apicmd = cmdstr
        self.keys = keys
        self.parselen = len(self.apicmd)
        try:
            runcmd = getattr(self,self.apicmd[0])
            runcmd(self.keys)

        except AttributeError, err:
            print "Console command not found: {}".format(self.apicmd[0])

    def domains(self,keys):

        print '=' * 90
        print 'Domains'
        print '=' * 90
        for key in keys['censys_io']['domains'].keys():
            print key
        print '=' * 90

    def hosts(self,keys,ip_address=None):

        for key in sorted(keys['censys_io']['domains'].keys()):
            print '=' * 90
            print '[ {} ]'.format(key)
            print '=' * 90
            for host in sort_ips(list(set(keys['censys_io']['domains'][key]['hosts'].keys()))):
                print '  -{}'.format(host)
            print ''

    def ports(self,keys,portnums=None):

        for key in sorted(keys['censys_io']['domains'].keys()):
            portlist = []
            print '=' * 90
            print '[ {} ]'.format(key)
            print '=' * 90
            for host in sort_ips(list(set(keys['censys_io']['domains'][key]['hosts'].keys()))):
                protos = keys['censys_io']['domains'][key]['hosts'][host]['protos']
                for obj in protos:
                    port = obj.split('/')[0].strip()
                    portlist.append(port)
            print ','.join(sort_ports(list(set(portlist))))
            print ''

    def protos(self,keys):

        for key in sorted(keys['censys_io']['domains'].keys()):
            protolist = []
            print '[ {} ]'.format(key)
            print '=' * 90
            for host in sort_ips(list(set(keys['censys_io']['domains'][key]['hosts'].keys()))):
                protos = keys['censys_io']['domains'][key]['hosts'][host]['protos']
                for obj in protos:
                    proto = obj.split('/')[1].strip()
                    protolist.append(proto)
            for proto in sorted(list(set(protolist))):
                print '  -{}'.format(proto)
        print '=' * 90

    def metrics(self,keys,type=None):

        print '=' * 90
        print "Censys IO Session Metrics"
        print '=' * 90
        print '{0:15} | {1:20}'.format('Total Domains',str(CensysMetrics(keys).total_domain_count()))
        print '{0:15} | {1:20}'.format('Total Hosts',str(CensysMetrics(keys).total_host_count()))
        print '=' * 90

    def sessions(self,keys):

        sessions = saved_sessions()

        if self.parselen == 2 and int(self.apicmd[1]) <= len(sessions.keys()):
            consolefile,consolekeys = switch_session(sessions[int(self.apicmd[1])])
            censys_shell(consolefile,consolekeys)

        else:
            print '=' * 90
            print 'Available Console Sessions'
            print '=' * 90
            for session in sessions:
                print '{}- {}'.format(session,sessions[session])
            print '=' * 90

    def history(self,keys,session_name=None):
        '''Handles the saved Censys IO console
           command-line history'''
        history_exists = history_check()
        if history_exists:
            history_buf = load_history()
            history_buf_len = len(history_buf.split('\n'))
            for i in range(0,history_buf_len):
                print i,history_buf.split('\n')[i-1]

        else:
            create_history()
            history_buf = load_history()
            history_buf_len = len(history_buf.split('\n'))
            for i in range(0,history_buf_len):
                print i,history_buf.split('\n')[i-1]

    def fprints(self,keys,fprint=None):
        pass

    def vulns(self,keys,filter=None):
        pass

    def report(self,keys,filter=None):
        pass

class CensysMetrics:

    def __init__(self,keys):

        self.keys = keys

    def total_domain_count(self):

        domains = self.keys['censys_io']['domains'].keys()
        domaincount = len(domains)
        return domaincount

    def total_host_count(self,domain_name=None):

        domains = self.keys['censys_io']['domains'].keys()
        if domain_name:
            for domain in domains:
                if domain == domain_name:
                    hosts = self.keys['censys_io']['domains'][domain]['hosts'].keys()
                    hostcount = len(hosts)
                    return hostcount

                else:
                    continue
        else:
            domain_host_total = []
            for domain in self.keys['censys_io']['domains'].keys():
                domaincount = len(self.keys['censys_io']['domains'][domain]['hosts'].keys())
                domain_host_total.append(domaincount)
            return sum(domain_host_total)

    def total_port_count(self):
        '''Returns total number of all unique ports in session'''
        portlist = []
        for domain in self.keys['censys_io']['domains'].keys():
                hosts = self.keys['censys_io']['domains'][domain]['hosts'].keys()
                for host in hosts:
                    protos = self.keys['censys_io']['domains'][domain]['hosts'][host]['protos']
                    for p in protos:
                        port = p.split('/')[0]
                        portlist.append(port)
        return len(list(set(portlist)))

    def total_proto_count(self):
        '''Returns total number of all unique protocols
           in session'''
        protolist = []


def censys_help():
    '''Censys full help menu. Todo
       includes integration into CensysHelp
       class.'''
    print '''
================================================================================
Censys API Commands
================================================================================
search
view
query

================================================================================
Censys Console Commands
================================================================================
domains
hosts
ports
protos
fprints
metrics
sessions
history
report
vulns
help
exit
================================================================================
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

def json_loader(jfile):
    '''Loads JSON data from file'''
    with open(jfile, 'r') as jdata:
        sdata = json.load(jdata)
        return sdata

def new_keys():
    '''Creates new JSON key blob for
       console session.'''
    keys = {'censys_io':{'domains':{}}}
    return keys

def create_session(sfile):
    '''Creates a new Censys IO console session'''
    skeys = new_keys()
    json_writer(skeys, sfile)
    print "Censys IO console session created."

def create_history():
    os.system('touch {}/.censys_io_history'.format(os.getcwd()))

def load_history():
    with open('{}/.censys_io_history'.format(os.getcwd()),'r') as historyfile:
        return historyfile.read()

def write_history(cmd):
    with open('{}/.censys_io_history'.format(os.getcwd()),'a') as historyfile:
        historyfile.write('{}\n'.format(cmd))

def api_method(endpoint):
    '''Function to check existence of
       user-supplied API endpoint'''
    methods = CENSYS_KEYS['endpoints'].keys()
    for m in methods:
        if endpoint in CENSYS_KEYS['endpoints'][m].keys():
            return m

def history_check():
    '''Function to check if a CLI history
       file for Censys IO exists'''
    filepath = '{}/.censys_io_history'.format(os.getcwd())
    if len(glob.glob('{}/*'.format(filepath))) == 0:
        return False
    else:
        return True

def session_check(sfile):
    '''Checks if a session file exists'''
    checkfile = glob.glob(sfile)
    if len(checkfile) == 0:
        print "Console session not found: {}".format(checkfile)
        return False

    else:
        print "Console session found: {}".format(checkfile)
        return True

def saved_sessions():
    '''Returns a list of all currently saved
       session files.'''
    savedkeys = {}
    savecount = 1
    sessions = '{}/.sessions/'.format(os.getcwd())
    index = glob.glob('{}*'.format(sessions))
    for i in index:
        savedkeys.update({savecount: i})
        savecount += 1
    return savedkeys

def session_handler(sfile=None):
    '''Handles the current console session. If no session file
       is found, a new one will be made. If the session exists,
       the JSON data from that session file is loaded into memory.'''
    console_sessions = saved_sessions()
    if sfile:
        loadkeys = json_loader(sfile)
        return sfile,loadkeys

    else:
        current_session = '{}/.sessions/censys-io-{}.session'.format(os.getcwd(),date.today())
        if current_session not in console_sessions.values():
            print "Creating console session: {}".format(current_session)
            create_session('{}'.format(current_session))
            loadkeys = json_loader('{}'.format(current_session))
            return current_session,loadkeys

        else:
            loadkeys = json_loader('{}'.format(current_session))
            return current_session,loadkeys

def run_censys_command(cmd,ckeys,cfile):
    '''Small wrapper function to make command calls to
       the API and console command classes'''
    if cmd == 'exit':
        sys.exit()

    banner()
    print '-Console session loaded: {}'.format(cfile)
    print '-Type "help" for a full list of commands.'
    print '=' * 90
    print ''
    censys_io_commands = ['search','view','query','help']
    censys_console_commands = ['domains','hosts','ports','websites','protos','certs','tags','metrics','sessions','history','fprints','report']

    if cmd.split()[0] in censys_io_commands:
        CensysAPI(cmd.split(), ckeys)

    else:
        ConsoleAPI(cmd.split(), ckeys)

def switch_session(new_session):
    print "Changing session: {}".format(new_session)
    sessions = saved_sessions()
    newfile,newkeys = session_handler(sfile=new_session)
    return newfile,newkeys

def censys_shell(cfile,ckeys):
    '''The Censys IO console command shell
       function.'''
    sessions = saved_sessions()
    banner()
    prompt = '#censys_io ~> '
    print '-Console session loaded: {}'.format(cfile)
    print '-Type "help" for a full list of commands.'
    print '=' * 90
    print ''
    while True:
        cmd = raw_input(prompt)
        run_censys_command(cmd, ckeys, cfile)
        write_history(cmd)
        json_writer(ckeys,cfile)

def banner():
    '''Chooses a random banner from the ./banners path and
     prints it to STDOUT in the console window'''
    os.system('clear')
    banner_path = '{}/banners/'.format(os.getcwd())
    random_banner = random.choice(glob.glob('{}*'.format(banner_path)))
    with open(random_banner,'r') as banner:
        print banner.read().rstrip()

def main():
    '''The main function'''
    cfile,ckeys = session_handler()
    censys_shell(cfile,ckeys)

if __name__ == '__main__':
    main()
