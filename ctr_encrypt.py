#!/usr/bin/python


# Import modules
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
import base64




def CTR():
  nonce = Random.new().read(8)

  key = b'Sixteen byte key'

  msg = 'Attack at dawn'




  # Encrypt

  # Create encryptor, ask for plaintext to encrypt, then encrypt and print ciphertext
  encrypt_mode = AES.new(key, AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
  cipher_text = base64.b64encode(encrypt_mode.encrypt(msg))
  print cipher_text




  # Decryption
  # Create decryptor, then decrypt and print plain text
  encrypt_mode = AES.new(key, AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
  plain_text = encrypt_mode.decrypt(base64.b64decode(cipher_text))
  print plain_text


CTR()
