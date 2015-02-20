#!/usr/bin/python


# Import modules
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
import base64




def CTR():
    iv = Random.new().read(8)
    key = 'this is a 32 bit long message...'
    plaintext = 'this is my secret message'

    #encrypted = CTR_ENCRYPT(key, plaintext, iv)
    #print encrypted
    
    ''' 
    fo = open('dbpass', 'a')   
    fo.write(('%s') % encrypted)
    fo.write('\n')
    fo.close()
    '''
   
    fo = open('dbpass','r')
    encrypted = fo.read()
    print encrypted
    fo.close()
       

    decrypted = CTR_DECRYPT(key, encrypted, iv)
    print decrypted




def CTR_ENCRYPT(key, plaintext, iv):

    encryptor = AES.new(key, AES.MODE_CTR, counter=Counter.new(64, prefix=iv))
    ciphertext = base64.b64encode(encryptor.encrypt(plaintext))
    return ciphertext




def CTR_DECRYPT(key, ciphertext, iv):

    decryptor = AES.new(key, AES.MODE_CTR, counter=Counter.new(64, prefix=iv))
    decoded_text = decryptor.decrypt(base64.b64decode(ciphertext))
    return decoded_text



CTR()
