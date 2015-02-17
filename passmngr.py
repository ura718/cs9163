#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto import Random
import binascii
import base64
import argparse
import sys
import os





''' This function checks for duplicate entries in dbpass file '''

def CHKDUP(index, e_username, e_password):
    try:
      if os.path.exists('./dbpass'):
        print "check for duplicates entries. STILL NEEDS WORK!!!"
    	file = open('dbpass', 'r')

 	for line in file:
            index_line, user_line, pass_line = line.split(':')

 	    if index_line == index:
	        print index_line
    		username = ECB_DECRYPT(e_username)
    		password = ECB_DECRYPT(e_password)

 	    elif index_line == 'cbc':
                print index_line 
 	    elif index_line == 'ctr':
                print index_line 
    	file.close()

    except:
      raise
  
    




def PADDING(msg):
  return msg + (((16-len(msg) % 16)) * '\x00')





def UNPAD(msg):
  return msg.rstrip(b'\x00')





def DB(index, e_username, e_password):

    # Verify if credentials already exists in file before writing
    #CHKDUP(index, e_username, e_password) 

    print "Write credentials to db file"
  
    
    # open file for writing even if file does not exist
    cred = open('dbpass', 'a')
    cred.write(("%s:%s:%s") % (index,e_username, e_password))
    cred.write("\n")
    cred.close()







###################################################################################

def ECB_ENCRYPT(plaintext):
    # secret key 
    key = b'Sixteen byte key'

    # Encrypt
    encrypt_mode = AES.new(key, AES.MODE_ECB)
    cipher_text = encrypt_mode.encrypt(plaintext) 

    ''' Convert cipher into hex. You need this so it looks like one line '''
    cipher_text = cipher_text.encode('hex')
    return cipher_text





def ECB_DECRYPT(cipher_text):
    # secret key 
    key = b'Sixteen byte key'

    # Decrypt
    cipher_text = binascii.unhexlify(cipher_text)  # convert hex back to cipher
    encrypt_mode = AES.new(key, AES.MODE_ECB)
    plain_text = encrypt_mode.decrypt(cipher_text)
    return plain_text



###################################################################################



def CBC_ENCRYPT(iv, plaintext):
    block_size = 16

    # secret key 
    key = b'Sixteen byte key'


    # Encrypt
    encrypt_mode = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = base64.b64encode(iv + encrypt_mode.encrypt((PADDING(plaintext))))
    print cipher_text
    return cipher_text




def CBC_DECRYPT(iv, cipher_text):
    block_size = 16

    # secret key 
    key = b'Sixteen byte key'


    # Decrypt
    cipher_text = base64.b64decode(cipher_text)
    iv = cipher_text[:AES.block_size]
    encrypt_mode = AES.new(key, AES.MODE_CBC, iv)
    plain_text = UNPAD(encrypt_mode.decrypt(cipher_text[AES.block_size:]))
    return plain_text

###################################################################################






''' Main ECB function that starts up Encryption and Decryption mechanisms '''

def ECB(username, password):
    print "ECB selected: %s:%s" % (username,password)
    username = PADDING(username)
    password = PADDING(password)

    # Encrypt plaintext username and password
    e_username = ECB_ENCRYPT(username)
    e_password = ECB_ENCRYPT(password)
    print "%s:%s" % (e_username,e_password)

    index='ecb'
    DB(index, e_username, e_password) 


    # Decrypt username and password
    username = ECB_DECRYPT(e_username)
    password = ECB_DECRYPT(e_password)
    print "%s:%s" % (username,password)






def CTR(username, password):
    print "CTR selected: %s:%s" % (username,password)
    DB(username, password)





def CBC(username, password):
    print "CBC selected: %s:%s" % (username,password)
    username = PADDING(username)
    password = PADDING(password)

    # Encrypt plaintext username and password
    iv = os.urandom(16)
    e_username = CBC_ENCRYPT(iv, username)
    e_password = CBC_ENCRYPT(iv, password)
    print "%s:%s" % (e_username,e_password)


    index='cbc'
    DB(index, e_username, e_password) 


    # Decrypt username and password
    username = CBC_DECRYPT(iv, e_username)
    password = CBC_DECRYPT(iv, e_password)
    print "%s:%s" % (username,password)














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
