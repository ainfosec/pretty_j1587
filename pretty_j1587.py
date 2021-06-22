#!/usr/bin/env python3

import multiprocessing
import os, sys
import queue
import threading

import struct_from_J1587 as j1587
import itertools as it
import re, socket, json, logging
import canon_functions

from hv_networks.J1587Driver import J1708DriverFactory, set_j1708_driver_factory, J1587Driver

messages_parsed_count = 0
json_message = dict()
print_message = ""
whitelist_print = False

def get_nbytes_for_var_pids(pid,data):
  bsequence = doc["pid_fields"][str(pid)]["Sequence"]
  h = doc["pid_fields"][str(pid)]["ByteDef"][bsequence[0]]
  n = "Number of parameter data characters"
  if n in h:
    return data[0]
  else:
    return False

def calc_checksum(msg):
  return (~(sum(msg) & 0xff) + 1) & 0xff

def pid_not_in_whitelist(pid,msg,bytecount,single_double):
  """ Check if we are using a whitelist and if our PID is NOT in that list """
  global whitelist, whitelist_print
  if not msg: return False
  # Be sure we are interested in this PID
  if whitelist and pid not in whitelist:
    # Need to advance out PID "pointer"
    if bytecount == -1:
      del msg[0:]
    elif bytecount == 1:
      del msg[0]
    elif bytecount == 2:
      del msg[0:2]
    elif bytecount == 3:
      if pid not in single_double:
        num_bytes = msg[0] # This field defined for var-len pids
      elif pid in single_double:
        num_bytes = get_nbytes_for_var_pids(pid,msg)
        if not num_bytes:
          num_bytes = len(msg)
      del msg[0:num_bytes+1]
    print_message = ""
    return True
  whitelist_print = True
  return False

def parse_pidbytes(mid,msg):
  """ This takes a message without the mid, nor the checksum
      This function is nasty. Need to try and clean it up by dividing
      into more functions
  """
  global doc, json_message , print_message

  # TODO: These may mess with customdb files so check who overrides who
  single_repeat = [254,196,198,199,237,233,240,498,506,212,210,211,226]
  double_repeat = [450,505,223]
  # Be careful not to extend
  single_double = single_repeat[:]+double_repeat[:]
  pageval = 0
  json_message["PIDs"] = list()
  json_message["DATA"] = dict()

  while msg:

    # Will this affect calculated checksum? Probably,
    #   but I won't worry at this point
    # If we have 1708 messages, combine page extensions for
    #   1587 format parsing
    if msg[0] == 255:
      pageval,msg = shrink_page_extention_pids(msg)
    # Keep track of the current page value
    #   This is added to the value of the later given PIDs of the
    #   same message
    elif pageval != 0:
      msg[0] += pageval

    # Robustness for incorrect messages
    if msg is None: return False
    if not len(msg): return False

    # Get the PID for parsing
    pid = msg.pop(0)

    json_message["DATA"][pid] = dict()
    bytecount = j1587.get_bytecount_from_pid(pid)

    if pid_not_in_whitelist(pid,msg,bytecount,single_double): continue

    bytemessage = ""

    # This happens often if there are bytes in the
    #  message that should not be there (ie truckDuck insertion)
    if str(pid) not in doc["pid_fields"]:
        l.critical("PID not found 0x%x (%d)" % (pid,pid))
        l.debug([hex(x) for x in msg])
        continue
    bsequence = doc["pid_fields"][str(pid)]["Sequence"]

    # Add handling for single repeats from another index,
    #   where representation is like "nab1b2b3b4..."
    if pid not in single_repeat and re.match("[a-z]+[a-z]1[a-z]2[a-z]3[a-z]4",bsequence):
      l.info("single %d" % pid)
      single_repeat.append(pid)
    # Handling for n,a,b,c/d,c,c,c,c
    elif pid not in single_repeat and re.match("([a-z],)+[a-z]/[a-z],",bsequence):
      l.info("single2 %d" % pid)
      single_repeat.append(pid)

    # Double work
    # match naabbcc... removing the parenthesis from naa(bbcc...)
    elif pid not in single_double and re.match(".*((?P<n>[a-z])(?P=n){1})$",bsequence.replace("(","").replace(")","")) and check2(bsequence) and "..." in bsequence:
      l.info("double %d"%pid)
      double_repeat.append(pid)
    # match nababab...
    elif pid not in single_double and re.match(".*(?P<n>([a-z])[^\1])(?P=n)",bsequence) and "..." in bsequence:
      l.info("double2 %d"%pid)
      double_repeat.append(pid)

    # Be carefull not to extend
    single_double = single_repeat[:]+double_repeat[:]

    if do_json: json_message["PIDs"].append(pid)

    if not msg:
      l.error("Incomplete message for PID %d" % pid)
      continue

    json_message["DATA"][pid]["bytes_def"] = dict()

    if bytecount == -1:
      l.debug("Bytecount is %d" % bytecount)
      # Bytecount undefined, assume it is the rest of the message
      data = msg[0:]
      del msg[0:]
      l.warning("Bytecount undefined")

    elif bytecount == 1:
      l.debug("Bytecount is %d" % bytecount)
      data = [msg.pop(0)]
      # Single byte data was simple, only one byte in sequence
      bytemessage += "    0x%02x - " % data[0]
      try:
        bytemessage += doc["pid_fields"][str(pid)]["ByteDef"]["a"]
        json_message["DATA"][pid]["bytes_def"][data[0]] = doc["pid_fields"][str(pid)]["ByteDef"]["a"]
        if pid == 0: # Request param
          try:
            bytemessage += "\n\t\t("+doc["pids"][str(data[0])]+")"
          except Exception as e :
            l.critical(e)
            return False
      except:
        l.error("Invalid message")
        return False
      bytemessage += "\n"

    elif bytecount == 2:
      l.debug("Bytecount is %d" % bytecount)
      data = msg[0:2]
      del msg[0:2]
      # Two byte sequence
      for i in range(len(data)):
        bytemessage += "    0x%02x - " % data[i]
        try:
          bytemessage += doc["pid_fields"][str(pid)]["ByteDef"][bsequence[i]]
          json_message["DATA"][pid]["bytes_def"][data[i]] = doc["pid_fields"][str(pid)]["ByteDef"][bsequence[i]]
        except:
          l.error("Invalid message")
          return False
        bytemessage += "\n"

    elif bytecount == 3:
      l.debug("Bytecount is %d" % bytecount)
      if not pid: return
      if pid not in single_double:
        num_bytes = msg[0] # This field defined for var-len pids
      elif pid in single_double:
        num_bytes = get_nbytes_for_var_pids(pid,msg)
        if not num_bytes:
          num_bytes = len(msg)
      else:
        l.info("ISSUE %d" % pid)
        return
      data = msg[0:num_bytes+1]
      del msg[0:num_bytes+1]

      # PIDs with a weird sequence will get handled elsewhere
      special_pid = False
      if pid in single_double:
        special_pid = True
      elif not re.match("^[a-z]+$",doc["pid_fields"][str(pid)]["Sequence"]):
        special_pid = True

      # Multi-byte sequence
      for i in range(len(data)):
        # This will break on repeated value or optional value cases,
        #   so that is the difference b/w two-byte and multi-byte
        if special_pid: break
        bytemessage += "    0x%02x - " % data[i]
        try:
          bytemessage += doc["pid_fields"][str(pid)]["ByteDef"][bsequence[i]]
          json_message["DATA"][pid]["bytes_def"][data[i]] = doc["pid_fields"][str(pid)]["ByteDef"][bsequence[i]]
        except :
          l.error("Rest of message could not be handled")
          del json_message["DATA"][pid]
          return

        bytemessage += "\n"

    if str(pid) in doc["pids"]:
      meaning = doc["pids"][str(pid)]
    else:
      #raise KeyError("Pid %d not encountered in doc object" % pid)
      l.error("Bad packet: %s" % msg)
      return False


    if pregular:
      print_message += "PID 0x%02x (%d): %s\n" % (pid,pid,meaning)
      if verbosity > 0:
        print_message += "  _Resolution  : %s\n" % doc["pid_fields"][str(pid)]["Resolution"]
        print_message += "  _MaxRange    : %s\n" % doc["pid_fields"][str(pid)]["MaximumRange"]
        print_message += "  _UpdatePeriod: %s\n" % doc["pid_fields"][str(pid)]["TransmissionUpdatePeriod"]
        print_message += "  _DataType    : %s\n" % doc["pid_fields"][str(pid)]["DataType"]
        print_message += "  _DataLength  : %s\n" % doc["pid_fields"][str(pid)]["ParameterDataLength"]
        print_message += "  _Priority    : %s\n" % doc["pid_fields"][str(pid)]["MessagePriority"]
      # Order matters for output
      print_message += "  DATA: %s\n" % ", ".join(hex(x) for x in data)
      if verbosity > 0: print_message += bytemessage

    if do_json:
      json_message["DATA"][pid]["PID_DEF"] =  meaning
      json_message["DATA"][pid]["resolution"] = doc["pid_fields"][str(pid)]["Resolution"]
      json_message["DATA"][pid]["maximum_range"] = doc["pid_fields"][str(pid)]["MaximumRange"]
      json_message["DATA"][pid]["update_period"] = doc["pid_fields"][str(pid)]["TransmissionUpdatePeriod"]
      json_message["DATA"][pid]["data_type"] = doc["pid_fields"][str(pid)]["DataType"]
      json_message["DATA"][pid]["data_length"] = doc["pid_fields"][str(pid)]["ParameterDataLength"]
      json_message["DATA"][pid]["priority"] = doc["pid_fields"][str(pid)]["MessagePriority"]
      json_message["DATA"][pid]["bytes"] = data

    # Handle the special pids
    # >> Should get overwritten with custom database, which needs to be tested
    if pid == 194: # Need to do fancy things with pid/sid and fmis
      parse_194(mid,data)
    elif pid in single_repeat:
      # These pids all have repeating last byte seqs (ex: nabccccc...)
      parse_single_repeated_byte_seq(pid,data)
    elif "NodataassociatedwithPID" in doc["pid_fields"][str(pid)]["Sequence"]:
      pass
    elif pid in double_repeat:
      parse_double_repeated_byte_seq(pid,data)


def check2(seq):
  """ Check for consecutive bytes that repeat once (ex "bb"),
      and that no others have more consecutive bytes
      This function is a prevention of a horrific regex.
  """
  seq = seq.strip(".")
  old = ""
  status = False
  count = 0

  for x in seq:
    if x == old:
      count += 1
    elif x != old:
      count = 1
    if count > 2: return False
    elif count == 2: status = True
    old = x

  return status

def parse_double_repeated_byte_seq(pid,data):
  """ Handle PIDs whose definition for the byte sequence has
        every other byte repetition or two byte sequences.
  """
  global doc, print_message, json_message

  l.debug("double parsing pid: %d" % pid)
  bsequence = doc["pid_fields"][str(pid)]["Sequence"]
  bytemessage = ""

  # Remove ()
  bsequence = bsequence.replace("(","").replace(")","")
  # Take off ...
  bsequence = bsequence.strip(".")

  double    = False
  alternate = False
  inc       = 0
  incd      = False

  # nabccdd... seems like PID 223 is the only one right meow ;-)
  if re.match(".*((?P<n>[a-z])(?P=n){1})+?",bsequence):
    double = True

  # nababab
  elif re.match(".*(?P<n>([a-z])[^\1])(?P=n)",bsequence):
    alternate = True

  iterations = iter(range(len(data)))
  l.debug(bsequence)
  for i in iterations:
    bytemessage += "    0x%02x - " % data[i]

    # Grab the corresponding definition of the current byte
    if i > len(bsequence)-1:
      if double:
        tmpmsg = doc["pid_fields"][str(pid)]["ByteDef"][bsequence[-1]]
        # Decided to increment whatever number is in here
        m = re.match(".*([0-9])",tmpmsg)
        num = int(tmpmsg[m.start(1):m.end(1)])
        # Logic on incrementing every other time
        if not incd:
          inc += 1
          num += inc
          old_num = num
          incd = True
        elif incd:
          num = old_num
          incd = False
        bytemessage += tmpmsg[:m.start(1)]+str(num)+tmpmsg[m.end(1):]
        json_message["DATA"][pid]["bytes_def"][data[i]] = tmpmsg[:m.start(1)]+str(num)+tmpmsg[m.end(1):]
      elif alternate:
        # Nab the last or penultimate byte def (ie -1 or -2)
        k = i%len(bsequence)%2-2
        t = doc["pid_fields"][str(pid)]["ByteDef"][bsequence[k]]
        bytemessage += t
        json_message["DATA"][pid]["bytes_def"][data[i]] = doc["pid_fields"][str(pid)]["ByteDef"][bsequence[k]]

    else:
      bytemessage += doc["pid_fields"][str(pid)]["ByteDef"][bsequence[i]]
      json_message["DATA"][pid]["bytes_def"][data[i]] = doc["pid_fields"][str(pid)]["ByteDef"][bsequence[i]]

    bytemessage += "\n"

  if pregular and verbosity > 0: print_message += bytemessage


def parse_single_repeated_byte_seq(pid,data):
  """ Give meaning to the PIDs that have repeated byte sequences in
        their definitions.
  """
  global doc, print_message, json_message

  bsequence = doc["pid_fields"][str(pid)]["Sequence"]
  bytemessage = ""
  slash = False
  shift = 0

  if "..." not in bsequence and pid not in [254,192,448]:
    #raise ValueError("'...' not found in byte sequence for pid %d" % pid)
    l.error("'...' not found in byte sequence for pid %d" % pid)
    return False

  # nab1b2b3b4...
  if re.match("[a-z]+[a-z]1[a-z]2[a-z]3[a-z]4",bsequence):
    bsequence = re.sub("([a-z]+)([a-z])1[a-z]2[a-z]3[a-z]4","\\1\\2",bsequence)
  # n,a,b,c/d,c,c,c,c
  elif re.match("([a-z],)+[a-z]/[a-z],",bsequence):
    bsequence = bsequence.replace(",","").rstrip(bsequence[-1]) + bsequence[-1]
    slash = True

  # Strip trailing ellipsis
  bsequence = bsequence.strip(".")

  if "Number of parameter data characters" in doc["pid_fields"][str(pid)]["ByteDef"][bsequence[0]]:
    # Choosing to ignore cases like
    #  Number of parameter data characters = 4,
    # Being that the byte could still have a value other than the expected
    iterations = range(data[0]+1)
  else:
    iterations = range(len(data))

  for i in iterations:
    # Don't get hung up on bad message
    if i not in data: return

    bytemessage += "    0x%02x - " % data[i]
    # grab the corresponding definition of the current byte
    if i+shift > len(bsequence)-1:
      bytemessage += doc["pid_fields"][str(pid)]["ByteDef"][bsequence[-1]]
      json_message["DATA"][pid]["bytes_def"][data[i]] = doc["pid_fields"][str(pid)]["ByteDef"][bsequence[-1]]
    else:
      bytemessage += doc["pid_fields"][str(pid)]["ByteDef"][bsequence[i+shift]]
      json_message["DATA"][pid]["bytes_def"][data[i]] = doc["pid_fields"][str(pid)]["ByteDef"][bsequence[i+shift]]

      if slash and i < len(bsequence)-3 and bsequence[i+shift+1] == "/":
        bytemessage += "\n           OR\n"
        bytemessage += "         - "
        shift += 2
        bytemessage += doc["pid_fields"][str(pid)]["ByteDef"][bsequence[i+shift]]

    bytemessage += "\n"

  if pregular and verbosity > 0: print_message += bytemessage


def parse_194(mid,msg):
  """ PID 194 requires some special attention.
      This function parses its data.
  """

  global print_message, json_message
  # Just in case we need it later with all the crazy things
  #  getting changed here
  num_bytes = msg.pop(0)

  while msg:
    sid_pid = msg.pop(0)
    if msg:
        code_char = msg.pop(0)
    else: continue
    fault_inactive = False
    std_code = False
    is_sid = False
    occurrence_count = False

    if code_char & 128: # occurence count included
      if not msg:
        l.error("Occurrence count was NOT included")
        l.error("Invalid message")
        return False
      occurrence_count = msg.pop(0)
      occurrence = " "*9 + "- Occurrance count: %d" % occurrence_count
    else:
      occurrence = " "*9 + "- No occurrance count provided"

    if code_char & 64: # status
      fault_inactive = True

    if code_char & 32: # std or expansion
      std_code = True
    diag_code = " "*9 + "- Diagnostic code is %s" % "standard" if std_code else "expansion"

    if code_char & 16: # 1 = SID, 0 = PID
      is_sid = True
      sid_s = " "*4 + "0x%02x - SID: %s" % (sid_pid,sidbyte_meaning(mid,sid_pid))
    else:
      pid_s = " "*4 + "0x%02x - PID: %s" % (sid_pid,pidbyte_meaning(sid_pid))

    fmi = code_char & 15

    fmiinfo = " "*4 + "0x%02x" % code_char
    fmiinfo +=  " - 0x%02x - FMI: %s" % (fmi,fmibyte_meaning(fmi))

    if pregular and verbosity > 0:
      print_message += "%s\n" % sid_s if is_sid else pid_s
      print_message += fmiinfo + "\n"
      print_message += occurrence + "\n"
      print_message += " "*9 + "- Fault is %s\n" % ("inactive" if fault_inactive else "active")
      print_message += "%s\n" % diag_code

    if do_json:
      json_message["sid_or_pid"] = "%s" % sid_s if is_sid else pid_s
      json_message["occurrence"] = occurrence.strip()
      json_message["fmi_info"] = fmiinfo.strip()
      json_message["fault"] = "Fault is %s" % ("inactive" if fault_inactive else "active")
      json_message["diag_code"] = diag_code.strip()


def sidbyte_meaning(mid,byte):
  """ Given an MID and a byte, return its SID meaning """
  global doc
  sets = doc["sids_for_mids"]

  for k,v in sets.items():
    if str(mid) in v[0] and str(byte) in list(v[1].keys()):
      return sets[k][1][str(byte)]
    elif str(byte) in doc["xdev_sids"]:
      return doc["xdev_sids"][str(byte)]

  # Decided not to raise errors and just keep chugging
  #raise KeyError("MID %d and SID %d combination not found" % (mid,byte))
  l.critical("MID %d and SID %d combination not found" % (mid,byte))
  return False

def pidbyte_meaning(byte):
  """ Given a byte, return its PID meaning """
  global doc
  if str(byte) in doc["pids"]:
    return doc["pids"][str(byte)]
  else:
    #raise KeyError("Pid %d not found in pids of document" % byte)
    l.critical("Pid %d not found in pids of document" % byte)
    return False

def fmibyte_meaning(byte):
  """ Given a byte, return its FMI meaning """
  global doc
  if str(byte) in doc["fmis"]:
    return doc["fmis"][str(byte)]
  else:
    #raise KeyError("Fid %d not found in fmis of document" % byte)
    l.critical("Fid %d not found in fmis of document" % byte)
    return False

def shrink_page_extention_pids(msg):
  """ If there is a pid in the message with a page extension,
      convert it to be the larger single int value
      ex 255,1 -> 256  ...   255,255,1 -> 511 ...
      Return the current page value and new message
  """
  if not msg or len(msg) < 2:
      l.warning("NONE message")
      return (None,None)
  # Page extensions can only take place directly after the MID
  #  All the other ones are from the same page...
  val = 0
  while msg[0] == 255:
    val += msg.pop(0) + 1
    pageval = val
  val += msg.pop(0)
  # Put the new value back into the messages
  msg.insert(0,val)

  return (pageval,msg)

class FeederJ1708Driver:
  def __init__(self):
    self.message_queue = multiprocessing.Queue()
    self.stopped = threading.Event()
    return

  def read_message(self, checksum=False, timeout=0.5):
    if self.stopped.is_set():
      return None

    msg = None
    try:
      msg = self.message_queue.get(block=True, timeout=timeout)
    except queue.Empty:
      pass
    return msg

  def send_message(self, buf, has_check=False):
    return

  def close(self):
    self.stopped.set()
    self.message_queue.close()

  def __del__(self):
    self.close()

  def put(self, obj):
    self.message_queue.put(obj)


class FeederJ1708Factory(J1708DriverFactory):
  def __init__(self):
    self.a_lock = threading.Lock()
    with self.a_lock:
      self.memo_fake_driver = None
    super(FeederJ1708Factory, self).__init__()

  def make(self):
    with self.a_lock:
      if self.memo_fake_driver is None:
        self.memo_fake_driver = FeederJ1708Driver()
      a = self.memo_fake_driver
    return a

  def clear(self):
    with self.a_lock:
      self.memo_fake_driver = None


class PyHvNetworksTransportReassemblerQueue:
  def __init__(self, suppress_fragments):
    self.suppress_fragments = suppress_fragments
    self.fake_j1708_factory = FeederJ1708Factory()
    set_j1708_driver_factory(self.fake_j1708_factory)
    self.j1708_driver = self.fake_j1708_factory.make()
    self.j1587_driver = J1587Driver(0x00, suppress_fragments=suppress_fragments,
                                    preempt_cts=True, silent=True, reassemble_others=True)

  def put(self, message):
    self.j1708_driver.put(message)

  def get(self, block=True, timeout=None):
    return self.j1587_driver.read_message(block, timeout)

  def close(self):
    self.fake_j1708_factory.clear()
    self.j1587_driver.cleanup()


def canonicalize(line):
  """ Parse the message.
      If checksum specified, we know it is included,
      so test it. If not, create it.
  """
  global doc, messages_parsed_count, canon_function, json_message
  global print_message, checksums, whitelist_print

  if not line or len(line) == 0 or line[0] == "," or line[-1] == ",":
    l.error("Invalid message: %s" % line)
    return

  if canon_function:
    msg = canon_function(line)
  else:
    msg = canon_functions.canon_besteffort(line)
  return msg


def pretty_print_all(message_queue, block=True, timeout=1):  # TODO no timeout (requires queue EOF in py-hv-networks)
  while True:
    try:
      msg = message_queue.get(block=block, timeout=timeout)
      if msg is None:
        return
      msg = list(msg)  # pretty_j1587 deals in lists of ints
      pretty_print(msg)
    except queue.Empty:
      break
    except KeyboardInterrupt:
      break
  return


def pretty_print(msg):
  global doc, messages_parsed_count, canon_function, json_message
  global print_message, checksums, whitelist_print

  if pregular:
    print_message += "MSG: [%s]\n" % ",".join(hex(x) for x in msg)
    if verbosity > 1: print_message += "     (%s)\n" % msg
  json_message["MSG"] = msg

  if len(msg) > 21:
    l.warning("Message is longer than the vehicle-in-motion maximum of 21 bytes")

  mid = msg[0]
  if checksums:
    calculated_checksum = calc_checksum(msg[:-1])
    message_checksum = msg[-1]
    if hex(message_checksum) == hex(calculated_checksum):
      if pregular: print_message += "MSG CHECKSUM: 0x%02x (%d)\n" % (message_checksum,message_checksum)
      json_message["MSG_CHECKSUM"] = message_checksum
    else:
      l.warning("-Message checksum not equal to calculated checksum-".upper())
      l.info("0x%02x <> 0x%02x"%(message_checksum,calculated_checksum))
  else:
    calculated_checksum = calc_checksum(msg)
    if pregular and verbosity > 1: print_message += "CLC CHECKSUM: 0x%02x (%d)\n" % (calculated_checksum,calculated_checksum)

  m = "MID 0x%02x (%d):  %s\n" % (mid,mid,doc["mids"][str(mid)])
  json_message["MID"] = mid
  json_message["MID_DEF"] = doc["mids"][str(mid)]
  json_message["CLC_CHECKSUM"] = calculated_checksum

  # Be specific about this being an on or off mid
  if mid == 10:
    m = m.replace("ON/OFF","ON")
    json_message["MID_DEF"] = doc["mids"][str(mid)].replace("ON/OFF","ON")
  elif mid == 11:
    m = m.replace("ON/OFF","OFF")
    json_message["MID_DEF"] = doc["mids"][str(mid)].replace("ON/OFF","OFF")
  if pregular: print_message += m

  # J1708 range
  if mid < 128 and mid > -1:
    if checksums:
      if pregular: print_message += "  DATA: %s\n" % ",".join(hex(x) for x in msg[1:-1])
      json_message["DATA"] = msg[1:-1]
    else:
      if pregular: print_message += "  DATA: %s\n" % ",".join(hex(x) for x in msg[1:])
      json_message["DATA"] = msg[1:]
  # J1587 range
  else:
    if checksums: parse_pidbytes(mid,msg[1:-1])
    else: parse_pidbytes(mid,msg[1:])

  # Maybe make the indent an arg for pretty printing json
  if do_json:
    if formatt: print(json.dumps(json_message,sort_keys=True,indent=formatt))
    else: print(json.dumps(json_message,sort_keys=True))

  if pregular:
    if whitelist:
      if whitelist_print:
        print(print_message)
      whitelist_print = False
    else:
      print(print_message)

  # Empty the message
  json_message = dict()
  print_message = ""

  # Print packet delimeter
  if pdelim:
    messages_parsed_count += 1
    print("\n-----------------%d-----------------\n" % messages_parsed_count)

  sys.stdout.flush()
  return


class TcpLineReceiver(threading.Thread):
  def __init__(self, port, out_queue):
    super().__init__()
    self.port = port
    self.out_queue = out_queue
    self.daemon = True

  def run(self):
    """ Get messages from TCP socket
        Use something like this from the client:
        cat <filename> | split -l 10 --filter "cat -" | nc -q0 <server> <port>
        Otherwise, reading fails due to weird packets. This should be addressed
        when there is time. The issue is getting a full line...
    """
    if not self.port: return

    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.bind(("0.0.0.0",int(self.port)))
    sk.listen(1)
    conn, addr = sk.accept()

    if conn:
      while True:
        data = conn.recv(1024)
        if data:
          data = data.decode('utf-8')
          for msg in data.split("\n"):
            if msg:
              self.out_queue.put(canonicalize(msg))


class UdpLineReceiver(threading.Thread):
  def __init__(self, port, out_queue):
    super().__init__()
    self.port = port
    self.out_queue = out_queue
    self.daemon = True

  def run(self):
    """ Get messages from UDP socket
        Use something like this from the client:
        cat <filename> | split -l 10 --filter "cat -" | nc -u -q0 <server> <port>
    """
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.bind(("0.0.0.0",int(self.port)))

    while True:
      data = sk.recv(1024)
      if data:
        data = data.decode('utf-8')
        for msg in data.split("\n"):
          if msg:
            self.out_queue.put(canonicalize(msg))


class TruckDuckUdpReceiver(threading.Thread):
  def __init__(self, interface_name, out_queue):
    super().__init__()
    self.out_queue = out_queue
    self.daemon = True

    self.port = 6970
    if interface_name == 'j1708_2' or interface_name == 'plc':
      self.port = 6972
    self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    self.sock.bind(('localhost', self.port))

  def run(self):
    while True:
      data = self.sock.recv(256)
      if data:
        self.out_queue.put(data)


class FilesReceiver(threading.Thread):
  def __init__(self, filenames, out_queue):
    super().__init__()
    self.filenames = filenames
    self.out_queue = out_queue
    self.daemon = True

  def run(self):
    for filename in self.filenames:
      if filename == "-":
        while True:
          msg = sys.stdin.readline()
          if not msg:
            break
          self.out_queue.put(canonicalize(msg))
      else:
        for msg in open(filename, "r").readlines():
          self.out_queue.put(canonicalize(msg))


# BIENVENUE
if __name__ == "__main__":

  import argparse as ap, threading as th

  parser = ap.ArgumentParser(description="Program to make sense of logged J1708/J1587 data")
  parser.add_argument("-c","--customdb",help="The filename of the file that contains the custom database in JSON format")
  parser.add_argument("-d",action="store_false",default=True,help="Disable default (grepable) output")
  parser.add_argument("-f","--filenames",help="The filename(s) of the file(s) that contain(s) the messages. Use - for stdin",nargs="?")
  parser.add_argument("-j","--canon",help="Use this function to reformat each line of input for parsing")
  parser.add_argument("-l",nargs="?",default="notset",choices=["critical","error","info","debug","notset"],help="Set the minimum level log level")
  parser.add_argument("-n","--nocache",action="store_true",help="Parse the J-specs every time command is run and generate a new cache file")
  parser.add_argument("-p",action="store_true",default=False,help="Print packet delimeters")
  parser.add_argument("-t",help="Define a TCP port to use as input")
  parser.add_argument("-u",help="Define a UDP port to use as input")
  parser.add_argument('--interface', default=None, const=None,
                      nargs='?', choices=['j1708', 'j1708_2', 'plc'],
                      help='choose the (TruckDuck) interface to dump from. NB: also enables --checksums')
  parser.add_argument("-v",nargs="?",default=0,type=int,help="Set the verbosity for regular output",choices=[0,1,2])
  parser.add_argument("-w","--whitelist",nargs="*",metavar="PID",type=int,help="List of PIDs to be parsed, ignoring other messages")
  parser.add_argument("-x","--checksums",action="store_true",help="Tells the parser that the messages contain checksums")
  parser.add_argument("--json",dest="do_json",default=False,action="store_true",help="Print JSON output as opposed to the default")
  parser.add_argument("--format",action="store_true",default=False,help="Pretty print the JSON output")
  args = parser.parse_args()

  # Do all the important stuff
  doc = j1587.get_document_object(customdb=args.customdb,nocache=args.nocache)

  # Setup nice logging
  levels = { "critical":50,"error":40,"warning":30,"info":20,"debug":10,"notset":0}
  l = logging.getLogger("pretty_1587")
  l.setLevel(levels[args.l])
  formatter = logging.Formatter('%(levelname)s : %(message)s')
  consolehandler = logging.StreamHandler()
  consolehandler.setLevel(levels[args.l])
  consolehandler.setFormatter(formatter)
  l.addHandler(consolehandler)

  # Set verbosity
  verbosity = args.v

  # Setup the PID whitelist
  whitelist = args.whitelist

  # Print packet delimeter
  pdelim = args.p

  # Print regular output?
  pregular = args.d

  # Are we trying to canonicalize?
  if args.canon:
    canon_function = getattr(canon_functions,args.canon)
  else:
    canon_function = getattr(canon_functions,'canon_besteffort')

  # Are we printing JSON
  do_json = args.do_json

  # How about pretty printing JSON
  formatt = args.format

  # Is checksum included
  checksums = args.checksums

  message_queue = PyHvNetworksTransportReassemblerQueue(suppress_fragments=True)

  timeout = None  # use 'follow' behaviour: wait forever (end with Ctrl-C) for all inputs except a regular file
  # Iterate through the provided files
  if args.filenames:
    if '-' not in args.filenames:
      timeout = None
    files_thread = FilesReceiver(args.filenames, message_queue)
    files_thread.start()

  # Setup udp and or tcp sockets for listening
  if args.interface:
    checksums = True
    truck_duck_thread = TruckDuckUdpReceiver(args.interface, message_queue)
    truck_duck_thread.start()
  if args.t:
    tcpthread = TcpLineReceiver(args.t, message_queue)
    tcpthread.start()
  if args.u:
    udpthread = UdpLineReceiver(args.u, message_queue)
    udpthread.start()

  pretty_print_all(message_queue, timeout=timeout)
