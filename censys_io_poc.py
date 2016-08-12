#!/usr/bin/python2

import sys
import os
import json
import requests

from argparse import ArgumentParser

CENSYS_API_ADDR = 'https://www.censys.io/api/v1'
CENSYS_API_ID = 'fe857b4f-99d5-4239-955a-90bd65ba75bc'
CENSYS_API_SECRET = 'A95Maw51wALQVGTJmtGSmMcTUraAxebV'
CENSYS_KEYS = {
               'endpoints':
                          {
                           'get':{
                                  'view':{
                                          'index':['ipv4','websites','certificates'],
                                          'api_path':'/view/'
                                         },
                                  'data':{
                                          'index':['series'],
                                          'api_path':'/data/'
                                         }
                                 },

                           'post':{
                                  'search':{
                                            'index':['ipv4','websites','certificates'],
                                            'api_path':'/search/'
                                           },
                                  'report':{'index':['ipv4','websites','certificates'],
                                            'api_path':'/report/'},
                                  'query':{
                                          'index':None,
                                          'api_path':'/query/'
                                          },
                                  'export':{
                                          'index':None,
                                          'api_path':'/export/'
                                           }
                                  }
                          }
             }


class CensysAPI:

    def __init__(self, apicommand, apikeys):
        self.apicmd = apicommand
        self.endkeys = apikeys

    def search(self):
        if self.apicmd[1] in self.endkeys['index']:
            search_url = CENSYS_API_ADDR + self.endkeys['api_path'] + self.apicmd[1]
            print search_url
            search_obj = requests.post(search_url, auth=(CENSYS_API_ID,CENSYS_API_SECRET), data=json.dumps({'query':self.apicmd[2]}))
            print search_obj.json()

    def view(self):
        if self.apicmd[1] in self.endkeys['index']:
            search_url = CENSYS_API_ADDR + self.endkeys['api_path'] + self.apicmd[1] + '/' + self.apicmd[2]
            print search_url
            search_obj = requests.get(search_url, auth=(CENSYS_API_ID,CENSYS_API_SECRET))
            print search_obj.json()

    def report(self):
        pass

    def query(self):
        pass

    def data(self):
        pass

    def export(self):
        pass

def api_method(endpoint):

    methods = CENSYS_KEYS['endpoints'].keys()
    for m in methods:
        if endpoint in CENSYS_KEYS['endpoints'][m].keys():
            return m

def main():

    endpoint = 'search'
    index = 'ipv4'
    query = 'defcon.org'
    method = api_method(endpoint)

    apikey = CENSYS_KEYS['endpoints'][method][endpoint]
    apicmd = [endpoint,index,query]

    load_api = CensysAPI(apicmd, apikey)

    if endpoint == 'search':
        load_api.search()

    elif endpoint == 'view':
        load_api.view()

    elif endpoint == 'data':
        load_api.data()

    elif endpoint == 'report':
        load_api.report()

    elif endpoint == 'query':
        load_api.query()

    elif endpoint == 'export':
        load_api.export()

    else:
        print "Endpoint not recognized."

if __name__ == '__main__':
    main()
