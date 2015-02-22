#!/usr/bin/python


#
# Author: Yuri Medvinsky
# class: cs9163 Application Security
# Info: This code imports ctr_class.py, cbc_class.py and ecb_class.py
#       to provide three different types of encryptions and decryptions.
#       It creates three different database files for storage of encrypted
#       usernames and passwords. Each database file is associated with the
#       chosen encryption. (e.g: -cbc ==> cbc_db)
#



# Import class modules
import argparse
from ctr_class import *
from cbc_class import *
from ecb_class import *









# Help Menu
parser = argparse.ArgumentParser()
parser.add_argument('-ctr', action='store_true', help='use ctr encryption')
parser.add_argument('-ecb', action='store_true', help='use ecb encryption')
parser.add_argument('-cbc', action='store_true', help='use cbc encryption')
parser.add_argument('-e', action='store_true', help='encrypt')
parser.add_argument('-d', action='store_true', help='decrypt')
parser.add_argument('-u', dest='u', help='provide username')
parser.add_argument('-p', dest='p', help='provide username')
args=parser.parse_args() 




# OPTIONS

flag = False
if args.ecb:
    c_ecb = args.ecb
    flag = True
if args.ctr:
    c_ctr = args.ctr
    flag = True
if args.cbc:
    c_cbc = args.cbc
    flag = True

if flag == False:
    print "[-] encryption mode required"
    sys.exit(0)










# Encrypt
if args.e:
    if args.u == None:
        print "[-] username required "
        sys.exit(0)

    if args.p == None:
        print "[-] password required "
        sys.exit(0)



    # CTR
    if args.ctr:
        # Instantiate ctr from CTR() class: "ctr_class"
        ctr = CTR()

        # check if db file exists
        ctr.chkdb()


        plaintext = args.u
        ctr.chkdup(plaintext)   # verify if duplicate username exists
        e_username = ctr.encrypt(plaintext)
                    
        plaintext = args.p
        e_password = ctr.encrypt(plaintext)

        fo = open('ctr_db', 'a')   
        fo.write(('%s:%s:%s') % (e_username, e_password, ctr.nonce))
        fo.write('\n')
        fo.close()




    # CBC
    if args.cbc:
        cbc = CBC()

        # check if db file exists
        cbc.chkdb()


        plaintext = args.u
        cbc.chkdup(plaintext)   # verify if duplicate username exists
        e_username = cbc.encrypt(plaintext)

        plaintext = args.p
        e_password = cbc.encrypt(plaintext)

        fo = open('cbc_db', 'a')
        fo.write(('%s:%s:%s') % (e_username, e_password, cbc.iv))
        fo.write('\n')
        fo.close()




    # ECB
    if args.ecb:
        ecb = ECB()

        # check if db file exists
        ecb.chkdb()


        plaintext = args.u
        ecb.chkdup(plaintext)   # verify if duplicate username exists
        e_username = ecb.encrypt(plaintext)

        plaintext = args.p
        e_password = ecb.encrypt(plaintext)

        fo = open('ecb_db', 'a')
        fo.write(('%s:%s') % (e_username, e_password))
        fo.write('\n')
        fo.close()









# Decrypt
if args.d:

    # CTR 
    if args.ctr:
        # Instantiate ctr from CTR() class: "ctr_class"
        ctr = CTR()


        plaintext = args.u
        file = []
        dict={}

        for f_lines in open('./ctr_db', 'r').readlines():
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




    # CBC
    if args.cbc:
        # Instantiate ctr from CTR() class: "ctr_class"
        cbc = CBC()

        plaintext = args.u
        file = []
        dict={}


        for f_lines in open('./cbc_db', 'r').readlines():
            f_lines = f_lines.strip('\n')
            file.append(f_lines)        


        for line in file:
            e_username, e_password, iv = line.split(':')
            username = cbc.decrypt(e_username, iv)
            password = cbc.decrypt(e_password, iv)
            dict[username] = password


        if dict.has_key(plaintext) == True:
            print dict[plaintext]
        else:
            print "no user found"




    # ECB
    if args.ecb:
        # Instantiate ctr from CTR() class: "ctr_class"
        ecb = ECB()

        plaintext = args.u
        file = []
        dict={}

        for f_lines in open('./ecb_db', 'r').readlines():
            f_lines = f_lines.strip('\n')
            file.append(f_lines)        

        for line in file:
            e_username, e_password = line.split(':')
            username = ecb.decrypt(e_username)
            password = ecb.decrypt(e_password)
            dict[username] = password


        if dict.has_key(plaintext) == True:
            print dict[plaintext]
        else:
            print "no user found"


