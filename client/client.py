#!/usr/bin/env python

import requests
import json
from requests.auth import HTTPBasicAuth

# create a new user
def create_user():
    url = 'http://127.0.0.1:5000/api/users'
    username = raw_input("[+] Enter username: ")
    password = raw_input("[+] Enter password: ")
    response = requests.post(url, json={"username":username, "password":password})
    print response.status_code


# get token for your user. This allows us to make authorized requests without sending
# creds all over the place.
def get_token():
    url = 'http://127.0.0.1:5000/api/token'
    username = raw_input("[+] Enter your username: ")
    password = raw_input("[+] Enter your password: ")    

    print "[+] Fetching token... "

    response = requests.get(url, auth=HTTPBasicAuth(username, password), verify=True)
    
    if(response.ok):
        jData = json.loads(response.content)
        user_token = jData['token']
        print "[+] Token:", jData['token']
    else: print "[!] ERROR!: ", response.status_code
    return user_token


# create new record
def create_record(user_token):
    url = 'http://127.0.0.1:5000/api/records/new'
    print '[+] Enter the values below to add a new record to the database...'

    ip = raw_input('[+] IP Address: ')
    uname = raw_input('[+] Username: ')
    key = raw_input('[+] SSH key: ')
    passw = raw_input('[+] Password: ')
    comments = raw_input('[+] Comments: ')

    response = requests.post(url, auth=HTTPBasicAuth(user_token, 'x'), json={'ip':ip, 'uname':uname, 'key':key, 'passw':passw, 'comments':comments})

    print response.status_code

def search_record(user_token):
    url = 'http://127.0.0.1:5000/api/records/get'
    response = requests.get(url, auth=HTTPBasicAuth(user_token, 'x'))
    print response.status_code


if __name__ == '__main__':
    while True:
        uinput = raw_input("What would you like to do? ")
        if uinput == "create user":
            create_user()
        elif uinput == "get token":
            token = get_token()
        elif uinput == "create record":
            print token
            create_record(token)
        elif uinput == "search record":
            search_record(token)
        else:
            print "blah you're wrong"
