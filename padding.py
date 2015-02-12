#!/usr/bin/python


# static key
key=b'12345678abcdefgh'

# 

# Input from terminal
msg=raw_input()

padding=len(msg)

counter=1

while True:
  if len(msg) == 0:
    print "message is empty"
    break
  elif padding % 16 != 0:
    padding = len(msg) + counter   
    print "%s + %s " % (len(msg),counter)
    counter = counter + 1
  elif padding % 16 == 0:
    break

# print message
print 'msg: %s + padding: %s' % (len(msg), counter-1)
