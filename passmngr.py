#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto import Random
import argparse
import sys
import os


#
# input user/pass and place encrypted pass into file
# you then take another input for user/pass and then 
# open the password file decrypt the pass for where user 
# is the same match up the passwords and if they are same
# then dont put it in. Otherwise put it in
#



''' This function checks for duplicate entries in dbpass file '''

def CHKDUP(username, password):
  try:
    if os.path.exists('./dbpass'):
      print "check for duplicates entries"
      
  except OSerror, e:
    pass
  
    





def DB(username, password):

  # Verify if credentials already exists in file before writing
  CHKDUP(username, password) 

  print "Write credentials to db file"
  

  # open file for writing even if file does not exist
  cred = open('dbpass', 'a')
  cred.write(("%s:%s") % (username, password))
  cred.write("\n")
  cred.close()




def ECB(username, password):
  print "ECB selected: %s:%s" % (username,password)
  DB(username, password) 



def CTR(username, password):
  print "CTR selected: %s:%s" % (username,password)
  DB(username, password)



def CBC(username, password):
  print "CBC selected: %s:%s" % (username,password)
  DB(username, password)






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
