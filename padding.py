#!/usr/bin/python


# static key
key=b'12345678abcdefgh'

# Input from terminal
msg=raw_input()

padding=len(msg)

counter=0

while True:
  if len(msg) == 0:
    print "message is empty"
    break
  elif padding % 16 != 0:
    counter = counter + 1
    padding = len(msg) + counter   
    numofzero = counter
    print "%s + %s " % (len(msg),counter)
  elif padding % 16 == 0:
    break

# print message
print 'msg: %s + padding: %s' % (len(msg), counter)

# number of null characters to be added to msg
print 'msg: \"%s\"' % (str(msg) + (' ' * numofzero))


