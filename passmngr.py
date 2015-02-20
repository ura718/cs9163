#!/usr/bin/python

#
# Author: Yuri Medvinsky
# Date: 02.17.2015
# class: cs9163
# Password Manager: Write three encryptions CTR, CBC and ECB for user input to store username and password 
#




from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
import binascii
import base64
import argparse
import sys
import os


#####################################################################
#
# 		ECB  -  ENCRYPTION
#
#####################################################################

def ECB(username, password):
    index='ecb'


    print "ECB selected: %s:%s" % (username,password)
    padded_username = PADDING(username)
    padded_password = PADDING(password)

    # Encrypt plaintext username and password
    e_username = ECB_ENCRYPT(padded_username)
    e_password = ECB_ENCRYPT(padded_password)
    print "%s:%s" % (e_username,e_password)

    # Verify if credentials already exists in file before writing. 
    ECB_CHKDUP(index, e_username, e_password, username, password) 





'''

Do duplicate entries exist?...

'''




def ECB_CHKDUP(index, e_username, e_password, username, password):
    print "check for duplicates entries."

    # put file dbpass content into array "file" 
    try:
        if os.path.exists('./dbpass'):
            file = []
            for f_lines in open('./dbpass','r').readlines():
                f_lines = f_lines.strip('\n')
                file.append(f_lines)
        else:
    	    ECB_COMMIT(index, e_username, e_password) 
    except:
      pass



    

    try: 
	# Counter will count to 0. If no entries are found then add new entries to dbpass file
        counter=len(file)

        for line in file:
            counter = counter - 1

            index_line = line.split(':')[0]
   

 	    if index_line == 'ecb' and index == 'ecb':

                index_line, fe_username, fe_password = line.split(':')


    	        f_username = UNPAD(ECB_DECRYPT(fe_username))	# username decrypted from file, then unpad
    	        f_password = UNPAD(ECB_DECRYPT(fe_password))	# password decrypted from file, then unpad

                # flag=ym
                #print "f_username: %s, f_password: %s, username: %s, password: %s" % (f_username, f_password, username, password)
	
	        # Check if username exists in a file, if it does then compare credentials from file with current input	
	        if f_username == username and f_password == password:
                    print "credentials already exist in database."
                    sys.exit(0)

                elif f_username != username and f_password != password and counter == 0:
                    print "writing to db file - ecb : %s:%s " % (username, password) 
    	            ECB_COMMIT(index, e_username, e_password) 

                elif f_username != username and f_password == password and counter == 0:
                    print "writing to db file - ecb : %s:%s " % (username, password) 
    	            ECB_COMMIT(index, e_username, e_password) 

                elif f_username == username and f_password != password and counter == 0:
                    print "writing to db file - ecb : %s:%s " % (username, password) 
    	            ECB_COMMIT(index, e_username, e_password) 


	    
            if index_line is None and counter == 0:
                print "writing to db file - ecb : %s:%s " % (username, password) 
    	        ECB_COMMIT(index, e_username, e_password) 


            if index_line != index and counter == 0:
                print "writing to db file - ecb : %s:%s " % (username, password) 
    	        ECB_COMMIT(index, e_username, e_password) 
            

                
    except UnboundLocalError, e:
        raise




'''

Now lets write encrypted credentials into dbpass file

'''



def ECB_COMMIT(index, e_username, e_password):

    print "Wrote credentials to db file"
  
    
    # open file for writing even if file does not exist
    cred = open('dbpass', 'a')
    cred.write(("%s:%s:%s") % (index, e_username, e_password))
    cred.write("\n")
    cred.close()



'''

Encrypt ECB plaintext

'''



def ECB_ENCRYPT(plaintext):
    # secret key 
    key = b'Sixteen byte key'

    # Encrypt
    encrypt_mode = AES.new(key, AES.MODE_ECB)
    cipher_text = encrypt_mode.encrypt(plaintext) 

    ''' Convert cipher into hex. You need this so it looks like one line '''
    cipher_text = cipher_text.encode('hex')
    return cipher_text



'''

Decrypt ECB cipher_text 

'''


def ECB_DECRYPT(cipher_text):
    # secret key 
    key = b'Sixteen byte key'

    # Decrypt
    cipher_text = binascii.unhexlify(cipher_text)  # convert hex back to cipher
    encrypt_mode = AES.new(key, AES.MODE_ECB)
    plain_text = encrypt_mode.decrypt(cipher_text)
    return plain_text










#####################################################################
#
# 		CBC  -  ENCRYPTION
#
#####################################################################

def CBC(username, password):
    index='cbc'

    print "CBC selected: %s:%s" % (username,password)
    #username = PADDING(username)
    #password = PADDING(password)

    # Encrypt plaintext username and password
    iv = os.urandom(16)
    e_username = CBC_ENCRYPT(iv, PADDING(username))
    e_password = CBC_ENCRYPT(iv, PADDING(password))
    print "%s:%s" % (e_username, e_password)


    # Verify if credentials already exists in file before writing
    CBC_CHKDUP(index, e_username, e_password, username, password, iv) 









def CBC_CHKDUP(index, e_username, e_password, username, password, iv):
    print "check for duplicates entries."

    # put file dbpass content into array "file" ; otherwise write to dbpass as new file
    try:
        if os.path.exists('./dbpass'):
            file = []
            for f_lines in open('./dbpass','r').readlines():
                f_lines = f_lines.strip('\n')
                file.append(f_lines)
        else:
    	    CBC_COMMIT(index, e_username, e_password, iv) 
    except:
      pass




    try:
	# Counter will count to 0. If no entries are found then add new entries to dbpass file
        counter=len(file)

        for line in file:
            counter = counter - 1

            index_line = line.split(':')[0]


            if index_line == 'cbc' and index == 'cbc':
                index_line, fe_username, fe_password, iv = line.split(':')

                f_username = UNPAD(CBC_DECRYPT(iv, fe_username))	# username decrypted from file, then unpad
                f_password = UNPAD(CBC_DECRYPT(iv, fe_password))	# password decrypted from file, then unpad
              
		
		#flag = ym2

                if f_username == username and f_password == password:
                    print "credentials already exist in database."
                    sys.exit(0)

                elif f_username != username and f_password != password and counter == 0:
                    print "writing to db file - cbc : %s:%s " % (username, password) 
    	            CBC_COMMIT(index, e_username, e_password, iv) 

		elif f_username != username and f_password == password and counter == 0:
                    print "writing to db file - cbc : %s:%s " % (username, password) 
    	            CBC_COMMIT(index, e_username, e_password, iv) 

		elif f_username == username and f_password != password and counter == 0:
                    print "writing to db file - cbc : %s:%s " % (username, password) 
    	            CBC_COMMIT(index, e_username, e_password, iv) 


            if index_line is None and counter == 0:
                print "writing to db file + cbc : %s:%s " % (username, password) 
    	        CBC_COMMIT(index, e_username, e_password, iv) 

            if index_line != index and counter == 0:
                print "writing to db file + cbc : %s:%s " % (username, password) 
    	        CBC_COMMIT(index, e_username, e_password, iv) 
                
    except UnboundLocalError, e:
        raise










def CBC_COMMIT(index, e_username, e_password, iv):

    print "Wrote credentials to db file"
  
    
    # open file for writing even if file does not exist
    cred = open('dbpass', 'a')
    cred.write(("%s:%s:%s:%s") % (index, e_username, e_password, iv))
    cred.write("\n")
    cred.close()







def CBC_ENCRYPT(iv, plaintext):
    block_size = 16

    # secret key 
    key = b'Sixteen byte key'


    # Encrypt
    encrypt_mode = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = base64.b64encode(iv + encrypt_mode.encrypt((PADDING(plaintext))))
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










#####################################################################
#
# 		CTR  -  ENCRYPTION
#
#####################################################################


def CTR(username, password):
    index='ctr'

    print "CTR selected: %s:%s" % (username,password)

    nonce = Random.new().read(8)
    

    # Encrypt plaintext username and password
    e_username = CTR_ENCRYPT(nonce, username)
    e_password = CTR_ENCRYPT(nonce, password)
    print "%s:%s" % (e_username,e_password)


    # Verify if credentials already exists in file before writing
    CTR_CHKDUP(index, e_username, e_password, username, password, nonce) 






def CTR_CHKDUP(index, e_username, e_password, username, password, nonce):
    print "check for duplicates entries."

    # put file dbpass content into array "file" 
    try:
        if os.path.exists('./dbpass'):
            file = []
            for f_lines in open('./dbpass','r').readlines():
                f_lines = f_lines.strip('\n')
                file.append(f_lines)
        else:
    	    CTR_COMMIT(index, e_username, e_password, nonce) 
    except:
      pass



    try:
	# Counter will count to 0. If no entries are found then add new entries to dbpass file
        counter=len(file)

        for line in file:
            counter = counter - 1

            index_line = line.split(':')[0]

            if index_line == 'ctr' and index == 'ctr':
                index_line, e_username, e_password, nonce = line.split(':')
                f_username = CTR_DECRYPT(nonce, e_username)	# username decrypted from file
                f_password = CTR_DECRYPT(nonce, e_password)	# username decrypted from file

                if f_username:
                    if f_username == username and f_password == password:
                        print "credentials already exist in database."
                        sys.exit(0)
                    else:
                        print "writing to db file - ctr : %s:%s " % (username, password) 
                        CTR_COMMIT(index, e_username, e_password, nonce) 

            elif index_line == ' ':
                print "writing to db file + ctr : %s:%s " % (username, password) 
    	        CTR_COMMIT(index, e_username, e_password, nonce) 

            elif counter == 0:
                print "writing to db file + ctr : %s:%s " % (username, password) 
    	        CTR_COMMIT(index, e_username, e_password, nonce) 
                
    except UnboundLocalError, e:
        pass






def CTR_COMMIT(index, e_username, e_password, nonce):

    print "Wrote credentials to db file"
  
    
    # open file for writing even if file does not exist
    cred = open('dbpass', 'a')
    cred.write(("%s:%s:%s:%s") % (index, e_username, e_password, nonce))
    cred.write("\n")
    cred.close()



def CTR_ENCRYPT(nonce, plaintext):

    # secret key
    key = b'Sixteen byte key'

    # Encrypt
    # Create encryptor, ask for plaintext to encrypt, then encrypt and print ciphertext
    encrypt_mode = AES.new(key, AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
    cipher_text = base64.b64encode(encrypt_mode.encrypt(plaintext))
    return cipher_text




def CTR_DECRYPT(nonce, cipher_text):

    # secret key
    key = b'Sixteen byte key'

    # Decryption
    # Create decryptor, then decrypt and print plain text
    encrypt_mode = AES.new(key, AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
    plain_text = encrypt_mode.decrypt(base64.b64decode(cipher_text))
    return plain_text





###################################################################################











def PADDING(msg):
  return msg + (((16-len(msg) % 16)) * '\x00')


def UNPAD(msg):
  return msg.rstrip(b'\x00')






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
