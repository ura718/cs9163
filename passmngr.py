#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto import Random
import argparse


def ECB(username):
  print "%s" % (username)




def main():
  # Help Menu
  parser = argparse.ArgumentParser()
  parser.add_argument('-ecb', action='store_true', help='use ecb encryption')
  parser.add_argument('-ctr', action='store_true', help='use ctr encryption')
  parser.add_argument('-cbc', action='store_true', help='use cbc encryption')
  parser.add_argument('-u', help='provide username')
  parser.add_argument('-p', help='provide password')
  args=parser.parse_args()  



  # OPTIONS 
  if args.ecb:
    c_ecb = args.ecb

  if args.ctr:
    c_ctr = args.ctr

  if args.cbc:
    c_cbc = args.cbc

  if args.u:
    username = args.u

  if args.p:
    password = args.p
    


  #if c_ecb and username and password:
  #  print "got it"
  


 

   


if __name__ == "__main__":
    main()
