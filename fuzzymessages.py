#!/usr/bin/python

# Simple script to generate random, most likely incorrect 1587/1708 messages
# Used for robusteness testing

import random,socket,sys

dhost  = "localhost"
dport  = 4545
udptcp = "" if len(sys.argv) == 1 else sys.argv[1] 

def send_msg_tcp(msg):
  sock.send(msg) 
  # Delim
  sock.send("\n")

def send_msg_udp(msg):
  sock.sendto(msg,(dhost,dport))

def send_msg_stdout(msg):
  print(msg)

def gen_msg():
  l = ["%02x" % random.randint(0,255) for x in range(random.randint(1,20))]
  msg = ",".join(l)
  return msg

if __name__ == "__main__":
  # Time to spew packets
  if udptcp == "T":
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.connect((dhost,dport))
    send_msg = send_msg_tcp
  elif udptcp == "U":
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    send_msg = send_msg_udp
  else:
    send_msg = send_msg_stdout

  while True:
    msg = gen_msg()
    send_msg(msg)
