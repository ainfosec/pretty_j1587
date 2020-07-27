# File for functions that take in a line as a message, and output 
#   the message in the format [int,int,...]
# This is useful for handling input from different programs, while
#   making minimal mods to the parsing code

def canon_nexiq(msg):
  """
    Format is:
    13:48:06.1133090 - RX - 172 254 137 4 212 128 194 137
  """
  m = msg.strip().split(" ")[4:]
  newmsg = [int(x) for x in m]
  # print(newmsg)
  return newmsg

def canon_decimal(msg):
  """
    Format is:
    139,99,22
    Handler for messages that income as decimal, as opposed to hex
  """
  m = msg.strip().split(",")
  newmsg = [int(x) for x in m]
  return newmsg

def canon_nodelims(msg):
  """
    Format is:
      0a00f6 (case insensitive)
  """
  msg = msg.strip()
  return [int(msg[i:i+2],16) for i in range(0,len(msg),2)]
