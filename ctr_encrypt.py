#!/usr/bin/python


# Import modules
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
import base64


# Pad for short keys
pad = '# constant pad for short keys ##'

iv = Random.new().read(8)
key = 'this is a 32 bit long message!!!'

plaintext = 'this is my secret message'





# Encrypt
# counter for encryptor
ctr_e = Counter.new(64, prefix=iv)


# Create encryptor, ask for plaintext to encrypt, then encrypt and print ciphertext
encryptor = AES.new(key, AES.MODE_CTR, counter=ctr_e)
ciphertext = encryptor.encrypt(plaintext)
print ciphertext






# Decryption
# counter for decryption
ctr_d = Counter.new(64, prefix=iv)


# Create decryptor, then decrypt and print decoded text
decryptor = AES.new(key, AES.MODE_CTR, counter=ctr_d)
decoded_text = decryptor.decrypt(ciphertext)
print decoded_text




