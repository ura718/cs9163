#!/usr/bin/python


#
# Author: Yuri Medvinsky
# class: cs9163 Application Security
# Info: This code is a ECB class used by  
#       password manager to import
#       




# Import modules
from Crypto.Cipher import AES
from Crypto import Random
import binascii
import sys
import os



class ECB:
    def __init__(self):

        # 32-bit private key
        self.key = binascii.unhexlify('c6e60b68ce37e90e5ea08930b381af38')


    def encrypt(self, plaintext):
        encrypt_mode = AES.new(self.key, AES.MODE_ECB)
        ciphertext = encrypt_mode.encrypt(self.padding(plaintext))
        ciphertext = ciphertext.encode('hex')
        return ciphertext


    def decrypt(self, ciphertext):
        ciphertext = binascii.unhexlify(ciphertext)  # convert hex back to cipher
        encrypt_mode = AES.new(self.key, AES.MODE_ECB)
        plaintext = self.unpad(encrypt_mode.decrypt(ciphertext))
        return plaintext


    def chkdup(self, plaintext):
        file = []
        dict={}

        for f_lines in open('./ecb_db', 'r').readlines():
            f_lines = f_lines.strip('\n')
            file.append(f_lines)

        for line in file:
            e_username, e_password = line.split(':')
            username = self.decrypt(e_username)
            password = self.decrypt(e_password)
            dict[username] = password                                                   

        if dict.has_key(plaintext) == True:
            print "duplicate user found"
            sys.exit(0)



    def padding(self, plaintext):
        return plaintext + (((16-len(plaintext) % 16)) * '\x00')


    def unpad(self, plaintext):
        return plaintext.rstrip(b'\x00')


    def chkdb(self):
        # If file does not exist then create it
        if os.path.exists('./ecb_db'):
            pass
        else:
           fo = open('./ecb_db', 'w')
           fo.close() 




