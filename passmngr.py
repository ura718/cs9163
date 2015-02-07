#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto import Random
import argparse
import sys


def ECB(username):
  print "%s" % (username)




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
  ''' setting flag to coordinate and see if encryption was selected '''

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
  elif flag == True:
    print "[+] encryption provided"


   

  if args.u == None:
    print "[-] username required "
    sys.exit(0)
  else:
    print "[+] username provided "
    username = args.u

  if args.p == None:
    print "[-] password required "
    sys.exit(0)
  else:
    print "[+] password provided "
    password = args.p




  
    

 

   


if __name__ == "__main__":
    main()
