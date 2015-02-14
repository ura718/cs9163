#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto import Random
import binascii
import argparse
import sys
import os





''' This function checks for duplicate entries in dbpass file '''

def CHKDUP(username, password):
    try:
      if os.path.exists('./dbpass'):
        print "check for duplicates entries. STILL NEEDS WORK!!!"
    except OSerror, e:
      pass
  
    



def PADDING(password):
    # assign length of password to padding (e.g int() )
    padding=len(password)

    # set counter to zero; nullify numofzero
    counter=0
    numofzero=[]

    while True:
      if len(password) == 0:
        print "message is empty"
        break
      elif padding % 16 != 0:		# if doesnt divide by 16 evenly. Padding required
        counter = counter + 1
        padding = len(password) + counter
        numofzero = counter
      elif padding % 16 == 0:		# divides evenly into 16. Padding is not required
        break




    try:
      if numofzero: 
	  # concatenate msg + \x00 * numofzero to variable %s if padding is required
          #ECB('%s' % (str(msg) + ('\x00' * numofzero)))
          return('%s' % (str(password) + ('\x00' * numofzero)))
      else:
          # padding of zeros is not required so no concatenation is needed
          #ECB('%s' % (str(msg)))
          return('%s' % (str(password)))
    except UnboundLocalError, e:
        raise











def DB(username, password):

    # Verify if credentials already exists in file before writing
    CHKDUP(username, password) 

    print "Write credentials to db file"
  

    # open file for writing even if file does not exist
    cred = open('dbpass', 'a')
    cred.write(("%s:%s") % (username, password))
    cred.write("\n")
    cred.close()










def ECB(username, password):
    print "ECB selected: %s:%s" % (username,password)
    password = PADDING(password)


    key = b'Sixteen byte key'		# secret key

    # Encrypt
    encrypt_mode = AES.new(key, AES.MODE_ECB)
    cipher_text = encrypt_mode.encrypt(password)

    ''' Convert cipher into hex. You need this so it looks like one line '''
    cipher_text = cipher_text.encode('hex')
    print "ENCRYPT: %s " % cipher_text


    # Decrypt
    cipher_text = binascii.unhexlify(cipher_text)  # convert hex back to cipher
    encrypt_mode = AES.new(key, AES.MODE_ECB)
    plain_text = encrypt_mode.decrypt(cipher_text)
    print "DECRYPT: %s " % plain_text


    #DB(username, password) 



def CTR(username, password):
    print "CTR selected: %s:%s" % (username,password)
    DB(username, password)



def CBC(username, password):
    print "CBC selected: %s:%s" % (username,password)
    DB(username, password)












def main():
    # Help Menu
    parser = argparse.ArgumentParser()
    parser.add_argument('-ecb', action='store_true', help='use ecb encryption')
    parser.add_argument('-ctr', action='store_true', help='use ctr encryption')
    parser.add_argument('-cbc', action='store_true', help='use cbc encryption')
    parser.add_argument('-u', dest='u', help='provide username')
    parser.add_argument('-p', dest='p', help='provide password')
    args=parser.parse_args()  

  

    # OPTIONS 
    ''' setting flag to check if encryption was selected '''

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
      print "[-] encryption required"
      sys.exit(0)


   

    if args.u == None:
      print "[-] username required "
      sys.exit(0)
    else:
      username = args.u

    if args.p == None:
      print "[-] password required "
      sys.exit(0)
    else:
      password = args.p






    # BEGIN ENCRYPTION based on selected attributes
    if args.ecb:
      ECB(username, password)
    elif args.ctr:
      CTR(username, password)
    elif args.cbc:
      CBC(username, password) 
    

 


if __name__ == "__main__":
    main()
