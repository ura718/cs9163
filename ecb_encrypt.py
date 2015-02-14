#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto import Random
import binascii



''' Here we use ECB simplest encryption '''

def ECB(text):
    key = b'Sixteen byte key'		# secret key

    # Encrypt
    encrypt_mode = AES.new(key, AES.MODE_ECB)
    cipher_text = encrypt_mode.encrypt(text)

    ''' Convert cipher into hex. You need this so it looks like one line '''
    cipher_text = cipher_text.encode('hex')
    print "ENCRYPT: %s " % cipher_text


    # Decrypt
    cipher_text = binascii.unhexlify(cipher_text)  # convert hex back to cipher
    encrypt_mode = AES.new(key, AES.MODE_ECB)
    plain_text = encrypt_mode.decrypt(cipher_text)
    print "DECRYPT: %s " % plain_text






def PADDING(msg):
    # assign length of message to padding (e.g int() )
    padding=len(msg)

    # set counter to zero; nullify numofzero
    counter=0
    numofzero=[]

    while True:
      if len(msg) == 0:
        print "message is empty"
        break
      elif padding % 16 != 0:		# if doesnt divide by 16 evenly. Padding required
        counter = counter + 1
        padding = len(msg) + counter
        numofzero = counter
      elif padding % 16 == 0:		# divides evenly into 16. Padding is not required
        break




    try:
      if numofzero: 
	  # concatenate msg + \x00 * numofzero to variable %s if padding is required
          ECB('%s' % (str(msg) + ('\x00' * numofzero)))
      else:
          # padding of zeros is not required so no concatenation is needed
          ECB('%s' % (str(msg)))
    except UnboundLocalError, e:
        raise






# Input from terminal
msg=raw_input()

PADDING(msg)
