#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto import Random
import binascii



''' Here we use ECB simplest encryption '''

def ECB(text):
    key = b'Sixteen byte key'		# secret key

    #text='1234567812345678ABCDEFGHIJKLMNOP'

    # Encrypt
    encrypt_mode = AES.new(key, AES.MODE_ECB)
    cipher_text = encrypt_mode.encrypt(text)
    cipher_text = cipher_text.encode('hex')	# convert cipher into hex
    print cipher_text
    #print cipher_text.encode('hex')


    # Decrypt
    cipher_text = binascii.unhexlify(cipher_text)  # convert hex back to cipher
    encrypt_mode = AES.new(key, AES.MODE_ECB)
    plain_text = encrypt_mode.decrypt(cipher_text)
    print plain_text






def PADDING():

    # Input from terminal
    msg=raw_input()

    # assign length of message to padding (e.g int() )
    padding=len(msg)

    # set counter to zero
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
        #print "%s + %s " % (len(msg),counter)
      elif padding % 16 == 0:		# divides evenly into 16. Padding is not required
        break



    # number of null characters to be added to msg
    #print 'msg: \"%s\"' % (str(msg) + (' ' * numofzero))


    try:
      if numofzero: 
          ECB('%s' % (str(msg) + ('\x00' * numofzero)))
      else:
          ECB('%s' % (str(msg)))
    except UnboundLocalError, e:
        raise


PADDING()
