#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto import Random




''' Here we randomize initialization vector (iv) and append it to key '''

def RANDOM_ENCRYPTION():
  key = b'Sixteen byte key'		# secret key
  iv = Random.new().read(AES.block_size)

  # Encrypt
  encrypt_mode = AES.new(key, AES.MODE_CBC, iv)
  cipher_text = iv + encrypt_mode.encrypt(b'Attack at dawn!!')
  print cipher_text


  # Decrypt
  encrypt_mode = AES.new(key, AES.MODE_CBC, iv)
  plain_text = iv + encrypt_mode.decrypt(cipher_text)
  print plain_text






''' Here the initialization vector (iv) is static and append it to key '''

def STATIC_ENCRYPTION():

  # key = b'Sixteen byte key'
  # iv = 'This is an IV456'


  ''' Encryption - cipher_text must be of 16 byte multiple (e.g: 16, 32, 48...etc) '''
  encrypt_mode = AES.new('Sixteen byte key', AES.MODE_CBC, 'This is an IV456')
  cipher_text = encrypt_mode.encrypt("A really secret message... Not for prying eyes!!")
  print cipher_text

  # Decryption
  encrypt_mode = AES.new('Sixteen byte key', AES.MODE_CBC, 'This is an IV456')
  plain_text = encrypt_mode.decrypt(cipher_text)
  print plain_text





RANDOM_ENCRYPTION()
#STATIC_ENCRYPTION()


