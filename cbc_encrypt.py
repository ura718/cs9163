#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto import Random
import base64




''' Here we randomize initialization vector (iv) and append it to key '''


def padding(msg):
  return msg + (((16-len(msg) % 16)) * '\x00')
  #return msg + ((16-len(msg) % 16) * '{')


def unpad(msg):
  return msg.rstrip(b'\x00')
  #return msg.rstrip(b'{')



def CBC():
  block_size=16

  # secret key
  key = b'Sixteen byte key'		
  
  # input message
  msg='Attack at dawn'

  
  # Encrypt
  iv = Random.new().read(AES.block_size)
  encrypt_mode = AES.new(key, AES.MODE_CBC, iv)
  cipher_text = base64.b64encode(iv + encrypt_mode.encrypt((padding(msg))))
  print cipher_text


  # Decrypt
  cipher_text = base64.b64decode(cipher_text)
  iv = cipher_text[:AES.block_size]
  encrypt_mode = AES.new(key, AES.MODE_CBC, iv)

  plain_text = unpad(encrypt_mode.decrypt(cipher_text[AES.block_size:]))
  print plain_text



CBC()
