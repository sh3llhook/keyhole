#!/usr/bin/env python

import requests
import json
import json
import hashlib, binascii
import os
from requests.auth import HTTPBasicAuth
import base64
from Crypto.Cipher import AES
from Crypto import Random


def encrypt(key, string, iv):
    rtrn_val = []
    BS = 16

    PADDING = '{'
    pad = lambda s: s + (BS - len(s) % BS) * PADDING

    crypto_suite = AES.new(pad(key), AES.MODE_CBC, iv)
    cipher_text = crypto_suite.encrypt(pad(string))
    rtrn_val.append(cipher_text.encode('hex'))
    rtrn_val.append(iv)
    return cipher_text.encode('hex') #rtrn_val

def decrypt(key, string, iv):
    BS = 16
    #unpad = lambda s : s[0:-ord(s[-1])]
    PADDING = '{'
    pad = lambda s: s + (BS - len(s) % BS) * PADDING
   # pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

    decrypt_suite = AES.new(pad(key), AES.MODE_CBC, iv)
    string_de = string.decode('hex')
    plain_text = decrypt_suite.decrypt(string_de).rstrip('{')
    print plain_text



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
    # generating IV here so each row is the same. Makes DB work easier
    iv = os.urandom(16)
    url = 'http://127.0.0.1:5000/api/records/new'
    print '[+] Enter the values below to add a new record to the database...'
    ip = raw_input('[+] IP Address: ')
    uname = raw_input('[+] Username: ')
    key = raw_input('[+] SSH key: ')
    passw = raw_input('[+] Password: ')
    comments = raw_input('[+] Comments: ')
    password = raw_input("[+] Enter password for crypto: ")
    crypt_ip = encrypt(password, ip, iv)
    crypt_uname = encrypt(password, uname, iv)
    crypt_key = encrypt(password, key, iv)
    crypt_passw = encrypt(password, passw, iv)
    crypt_comments = encrypt(password, comments, iv)
    iv = unicode(iv, errors='ignore')

    #decrypt(password, crypt_ip[0], crypt_ip[1])

    response = requests.post(url, auth=HTTPBasicAuth(user_token, 'x'), json={\
                'ip':crypt_ip, \
                'uname':crypt_uname, \
                'key':crypt_key, \
                'passw':crypt_passw, \
                'comments':crypt_comments, \
                'iv':iv\
                }
                )

    print response.status_code

def search_record(user_token):
    url = 'http://127.0.0.1:5000/api/records/get'
    response = requests.get(url, auth=HTTPBasicAuth(user_token, 'x'))
    print response.status_code
    key = raw_input("[+] Enter your decryption password: ")

    data = json.loads(response.text)
    print data
    for k,v in data.iteritems():
        for k_i, v_i in v.iteritems():
            print v_i


if __name__ == '__main__':
    while True:
        print "create user, get token, create record, search record"
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
        elif uinput == "decrypt it":
            decrypt(raw_input('passworrrd: '), raw_input('cipher: ').strip(), raw_input('iv: ').strip())
        elif uinput == "test":
            #key, string-to-crypt, iv
            cipher_text = encrypt('bbbb', 'ccc')
            decrypt('bbbb', cipher_text[0], cipher_text[1])
        else:
            print "blah you're wrong"

