#!/usr/bin/python


# Import modules
import argparse
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
import base64
import sys



class CTR:
    def __init__(self):

        # Pick randome 64-bit bonce
        self.nonce = Random.new().read(8)
        self.key = b'Sixteen byte key'


    def encrypt(self, plaintext):
        encryptor = AES.new(self.key, AES.MODE_CTR, counter=Counter.new(64, prefix=self.nonce))
        ciphertext = base64.b64encode(encryptor.encrypt(plaintext))
        return ciphertext


    # ciphertext and nonce are taken from dbpass file
    def decrypt(self, ciphertext, nonce):
        decryptor = AES.new(self.key, AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
        plaintext = decryptor.decrypt(base64.b64decode(ciphertext))
        return plaintext


    def chkdup(self, plaintext):
        file = []
        dict={}

        for f_lines in open('./dbpass', 'r').readlines():
            f_lines = f_lines.strip('\n')
            file.append(f_lines)

        for line in file:
            e_username, e_password, nonce = line.split(':')
            username = self.decrypt(e_username, nonce)
            password = self.decrypt(e_password, nonce)
            dict[username] = password                                                   

        if dict.has_key(plaintext) == True:
            print "duplicate user found"
            sys.exit(0)




# Instantiate ctr with CTR() class
ctr = CTR()



# Help Menu
parser = argparse.ArgumentParser()
parser.add_argument('-ctr', action='store_true', help='use ctr encryption')
parser.add_argument('-e', action='store_true', help='encrypt')
parser.add_argument('-d', action='store_true', help='decrypt')
parser.add_argument('-u', dest='u', help='provide username')
parser.add_argument('-p', dest='p', help='provide username')
args=parser.parse_args() 





# encrypt
if args.e:

    plaintext = args.u
    ctr.chkdup(plaintext)   # verify if duplicate username exists
    e_username = ctr.encrypt(plaintext)
    
    plaintext = args.p
    e_password = ctr.encrypt(plaintext)

    fo = open('dbpass', 'a')   
    fo.write(('%s:%s:%s') % (e_username, e_password, ctr.nonce))
    fo.write('\n')
    fo.close()



# decrypt
if args.d:

    plaintext = args.u
    file = []
    dict={}
    
    for f_lines in open('./dbpass', 'r').readlines():
        f_lines = f_lines.strip('\n')
        file.append(f_lines)

    for line in file:

        e_username, e_password, nonce = line.split(':') 
        username = ctr.decrypt(e_username, nonce)
        password = ctr.decrypt(e_password, nonce)
        dict[username] = password                                                   


    if dict.has_key(plaintext) == True:
        print dict[plaintext]
    else:
        print "no user found"

