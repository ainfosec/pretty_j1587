#!/usr/bin/python

# This file will be used for scraping the data from the 1587 spec
#   into some nice structures to be used for message inspection

# TODO: #Maybe make these tickets/issues (but let's see where we are
#       #  once public)

#   1) Fix up weird sequences from the format sections
#     The spec here is making me angry due to inconsistencies. Some places they just repeat the letter to show repetion. Some places an ellipsis. In other instances, the '*' character is used as a delimeter and shown as such in the "Sequence" field. In other spots, it has a letter in the sequence field.
#   2) Multi-line summaries seem to be handled, but need to work with the PIDs that get filled in from other appendices
#   3) Datatypes that span multiple lines (ex: PID 500) need to be handled
#   4) Need to handle multi-line keys for the pid_fields dict
#   5) Handle bytes/bits definitions using the sequence
#        There is a lot of variation among the format definitions, for instance PID 206
#        this makes it very difficult to find a general solution for using the parsed content
#   6) Take out locations where I used hard-coded line numbers due to time 
#   7) PID 79 missing, may also want to check all PIDs and see what others
#
######################################################################

import re,os,pickle,itertools,json
import pprint as pp, logging as lg
import ConfigParser

config = ConfigParser.ConfigParser()
config.read("config.cfg")

# This file should be the output of : pdftotext -layout J1587_201301.pdf <filename>
filepath_layout_1587 = config.get("Filepaths","1587_filepath",0)
# This file should be the output of : pdftotext -layout J1708_201609.pdf <filename>
filepath_layout_1708 = config.get("Filepaths","1708_filepath",0)

# Lines with layout
fhl = open(filepath_layout_1587,"r")
linesl = fhl.readlines()
# 1708 lines with layout
fh1708l = open(filepath_layout_1708,"r")
lines1708 = fh1708l.readlines()

def get_mids(linesl):
  """ Return dictionary of mid:meaning """
  foundstartmids = False
  mids = {}

  for line in linesl:
    
    # Before table
    if not foundstartmids and "MID #" in line:
      foundstartmids = True  

    # MID table found
    elif foundstartmids:
      if re.match(' *[0-9]+',line.strip()): 
        s = re.split(' {3,}',line)
        # We only grab the Basic Heavy Duty Column
        #  otherwise s[3] for Mass Transit Specific, s[4] for Marine Specific
        mids[s[1]] = s[2] 

    # After table
    if "NOTE: Designers" in line:
      break

  return mids

def get_pids(linesl):
  """ 
  Required layout lines.  
  Returns dictionary of pid:meaning
  """
  pids = {}
  foundstartpids = False

  for line in linesl:
    # After table
    if "These PIDs are superseded by PIDs 194, 195, and 196." in line:
      break

    # Before table
    if not foundstartpids and "  TABLE 2 - PARAMETER IDENTIFICATION" in line:
      foundstartpids = True

    elif foundstartpids: 
      if re.match(' +[0-9]+[^\.]',line): 
        garbage,pid,meaning = re.split(" {9,}",line)
        pids[pid.strip()] = meaning.strip() 

  return pids

def get_fmis(linesl):
  """ Requres layout lines. Return dictionary of FMIs """
  foundstartfmis = False
  fmis = {}

  for line in linesl[1247:1265]:
    if "(that is" in line: continue
    fmi,meaning= re.split(" {5}",line.strip())
    fmis[fmi] = meaning

  if len(fmis) != 16:
    return -1

  return fmis


def get_diagnostic_sids():
  return {str(150+x):"System Diagnostic Code #"+str(x) for x in range(1,6)}

def get_common_sids(linesl): 
  """ Use the formatted lines. Return dictionary of common_sid:meaning """

  foundstartcsids = False
  common_sids = {}

  for line in linesl:

    if foundstartcsids and "Engine SIDs" in line:
      break

    if not foundstartcsids and "   Common SIDs" in line:
      foundstartcsids = True

    elif foundstartcsids:
      if re.match(' +[0-9]+[^\.]',line): 
        garbage,sid,meaning = re.split(" {9,}",line)
        common_sids[sid.strip()] = meaning.strip() 

  return common_sids


def get_xdevice_sids(linesl):
  """ Get the sids that are the same across devices """
  d = get_diagnostic_sids()
  d.update(get_common_sids(linesl))
  return d

def get_sids_for_mids(linesl):
  """ Get the sids that are related to specific mids as a dictionary """

  sets = {}
  regex = ".* SIDs *.*\( *MIDs? *="
  for line in linesl:
    if re.match(regex,line):
      group = line.split("(")[0].strip() 
      sids = re.findall("[0-9]+",line)
      sets[group] = [sids,{}]

  for group in sets.keys():
    if "Engine" in group:
      sid_dict = parse_sids_for_mid_group(group,"511",linesl)
    else:
      sid_dict = parse_sids_for_mid_group(group,"150",linesl)

    sets[group][1] = extend_dict(clean_ids(sid_dict))
    
  return sets

def parse_sids_for_mid_group(group,groupenddemarc,linesl):
  found = False
  dic   = {}

  for line in linesl:

    if not found and group in line:
      found = True

    elif found:
      if re.match(' +[0-9]+[^\.]',line): 
        try:
          sid,meaning = re.split(" {6,}",line.strip())
          dic[sid] = meaning
        except:
          print("Error parsing: %s",line)
          dbg(re.split(" {6,}",line.strip()))

      # last line we need
      if groupenddemarc in line: 
        break

  return dic 

def get_mids_from_1708(lines1708):
  mids = {}
  for line in lines1708[541:568]: 
    s = line.strip()
    if re.match("[0-9]{1,3}",s): 
      try:
        mid,meaning = re.split(" {6,}",s)
      except:
        mid = "125"
        meaning = meaning125
    else:
      m = re.split("\(",line.strip())
      if len(m) > 1: 
        meaning125 = m[1] + " J2497"

    mids[mid] = meaning
    
    if "88" in mid:
      mids[mid] = mids[mid] + ". Suggested for dynamic allocation in J2497."
    if "87" in mid:
      mids[mid] = mids[mid] + ". Signals ABS system is actively controlling ABS event."
    if "10" in mid and "110" not in mid:
      mids[mid] = mids[mid] + ". Trailer ABS indicator ON/OFF."

  return mids

def combine_mid_ranges(linesl,lines1708):
  d = get_mids_from_1708(lines1708)
  d = extend_dict(d)
  c = get_mids(linesl)
  c = extend_dict(c)
  # Be sure we are doing this in the right order
  c.update(d)
  return c

def clean_sids_for_mids(sids_for_mids):
  n = {}
  for k,d in sids_for_mids.iteritems():
    n[k] = clean_ids(d)
  return n
      
def clean_ids(ids):
  n = {}
  for k,v in ids.iteritems():
    if "(" in k: n[k[:k.find(" (")]] = v
    else: n[k] = v
  return n

def range_from_hyphenated(item): 
  key,meaning = item 
  splitchar = ""
  r = {} 

  if "-" in key: 
    splitchar = "-"
  elif "\xe2\x80\x94" in key:
    splitchar = "\xe2\x80\x94"
  elif "\xe2\x80\x93" in key:
    splitchar = "\xe2\x80\x93"
  
  if splitchar:
    rng = key.split(splitchar)
    r = {str(n):meaning for n in range(int(rng[0]),int(rng[1])+1)}

  else:
    r[key] = meaning

  return r

def extend_dict(d):
  # Take in dictionary of [msp]id:meanings and return expanded version
  r = {}
  for item in d.iteritems():
    res = range_from_hyphenated(item) 
    r.update(res) 
  return r

def get_next(it):
  """ Ignore the pdf junk that delineates pages, and blank lines """
  line = next(it)

  while True:
    if "\x0c" in line.strip(): line = next(it)
    elif "Downloaded from SAE International by" in line.strip(): line = next(it)
    elif " "*34+"J1587" in line.strip(): line = next(it)
    elif "_"*5 in line.strip(): line = next(it)
    elif not line.strip(): line = next(it)
    else: break
    
  return line

def combine_custom_database(filepath,doc):
  """
    Add or overwrite structs from custom database into our
    main object.
  """
  
  try:
    fd = open(filepath,"rb")
  # Made the decision to keep processing with original struct
  #   but print error
  except IOError as e:
    lg.error("IOError: %s" % e) 
    return doc

  override_dict = json.load(fd)
  fd.close()

  # doc.update(override_dict) is clobbering for some reason
  #   so do it more manually for now
  for k,v in override_dict.iteritems():
    doc[k].update(v)

  return doc

       
############################################################
# UTILS                                                    #
# These are functions we may want to call from elsewhere   #
############################################################

def dbg(s):
  pp.pprint(s)
  
def get_sid_mids():
  """ Return list of mids that have sid associations.
      Handy for quick check to see if next byte is an sid or pid,
      if I have interpreted the spec correctly.
  """
  l = [128, 175, 183, 184, 185,
       186, 130, 176, 223, 136, 
       137, 138, 139, 246, 247,
       140, 234, 142, 187, 188,
       143, 146, 200, 150, 151,
       157, 162, 191, 163, 166,
       167, 168, 169, 186, 178,
       190, 217, 218, 219, 222,
       232, 254, 248, 253, 177]
  return l 
  
def get_bytecount_from_pid(pid):
  """ 
     The pid is the calculated value, which could be composed of several
     bytes when using page extensions.
     Return the number of bytes the pid utilizes. 3 for n. -1 for unknown
  """
  bytes1 = [(0,127),(256,383),(512,639),(768,895)]
  bytes2 = [(128,191),(384,447),(640,703),(896,959)]
  bytesn = [(192,253),(448,509),(704,765),(960,1021)] 
  # 254 is proprietary data. I will put it under "variable" len, as it is not
  #  addressed in the spec, but we had it in our captures
  bytesn.append((254,254))
  for rng in bytes1:
    if pid in range(rng[0],rng[1]+1): return 1
  for rng in bytes2:
    if pid in range(rng[0],rng[1]+1): return 2
  for rng in bytesn:
    if pid in range(rng[0],rng[1]+1): return 3 
  return -1

def get_document_object(customdb="",nocache=False):
   
  global linesl,lines1708

  tmpfile = "/tmp/J1587_1708_2497_doc_obj"
  doc = {}


  # Use a cache in tmp dir
  if not os.path.exists(tmpfile) or nocache:
    doc["mids"]          = combine_mid_ranges(linesl,lines1708)
    doc["fmis"]          = get_fmis(linesl)
    doc["pids"]          = extend_dict(clean_ids(get_pids(linesl)))
    doc["xdev_sids"]     = extend_dict(get_xdevice_sids(linesl))
    doc["sids_for_mids"] = get_sids_for_mids(linesl)
    doc["pid_fields"]    = get_pid_fields(linesl)

    # Write the file to /tmp
    fh = open(tmpfile,"w")
    pickle.dump(doc,fh,pickle.HIGHEST_PROTOCOL)
    fh.close()

  else: 
    # Load the cached file
    # Reboot or cache file deletion will require 
    #   reparsing the spec documents
    fh = open(tmpfile,"r")
    doc = pickle.load(fh)
    fh.close()

  if customdb: doc = combine_custom_database(customdb,doc)

  return doc


def get_pid_fields(linesl):
  """ Parse the data from the appendix to be used for better PID detail 
      This one needs a bit more work.
      Appendix F and sequence work
  """

  pid_fields = {}
  line_iter = iter(linesl) 
  # Need to come up with a good way to get this
  summary = ""

  for line in line_iter:
   
    try:
      if re.match('^A\.[0-9]+',line):
        line = ""

        while not re.match('^A\.[0-9]+',line.strip()): 
          cont = True
          line = get_next(line_iter) 
          
          if "Parameter Data Length:" in line:
            cont = False
            pdl = line.split(":")[1].strip()
          elif "Data Type:" in line:
            cont = False
            dt = line.split(":")[1].strip()
          elif "Resolution:" in line:
            cont = False
            res = line.split(":")[1].strip()
          elif "Maximum Range:" in line:
            cont = False
            mr = line.split(":")[1].strip()
          elif "Transmission Update Period:" in line:
            cont = False
            tup = line.split(":")[1].strip()
          elif "Message Priority:" in line:
            cont = False
            mp = line.split(":")[1].strip()
          elif "Format:" in line:
            cont = False
            get_next(line_iter) # PID Data, which we discard
            line = get_next(line_iter) # [0-9]{1,3} [a-z]+
            line_l = [x for x in line.strip().split(" ") if x] 
            pid = line_l[0]
            seq = "".join(line_l[1:])

            # These are probably representative of optional params
            #   the issue is representing continuing sequences, which
            #   seems inconsistant
            #if '[' in seq: print(pid,seq)

            # Handle bytes/bits here
            bytedef = {}
            line = get_next(line_iter)
            while not re.match("^[A-F]\.[0-9]+",line.strip()):
            #while line.strip():

              # Found one case where the "\xe2\x80\x94" character was set as "-"
              #   in case this comes up somewhere else, I'll just do generic code
              if re.match(" *[a-z]-",line): 
                line = line.replace("-","\xe2\x80\x94")

              if "\xe2\x80\x94 " in line.strip():
                a,b = line.strip().split("\xe2\x80\x94 ")
                # Sometimes we get "a a", for 2 byte pids where both bytes
                #  represent the same value, which would be handled by sequence
                a = a.strip()[0]
                b = b.strip()
                bytedef[a] = b

              line = get_next(line_iter)
            # END inner WHILE

            # Put together dict for this pid
            pid_fields[pid] = {}
            pid_fields[pid]["ParameterDataLength"] = pdl
            pid_fields[pid]["DataType"] = dt
            pid_fields[pid]["Resolution"] = res
            pid_fields[pid]["MaximumRange"] = mr
            pid_fields[pid]["TransmissionUpdatePeriod"] = tup
            pid_fields[pid]["MessagePriority"] = mp
            pid_fields[pid]["Sequence"] = seq.replace("\xe2\x80\xa6","...")
            #if pid == "254": # I need to treat this one as variable length
             # pid_fields[pid]["Sequence"] += "..."
            pid_fields[pid]["ByteDef"] = bytedef # This should be nested dict
            if summary:
              pid_fields[pid]["Summary"] = summary
              summary = ""
            # ENDIF Format

          else:
            ls = line.strip()
            # Need to handle multi-lines better here
            if re.match("[a-zA-Z]+ ",ls):
              if not cont:
                summary = ls
                cont = True
              else:
                summary += ls

          # Reset summary if we are on a line in the appendix
          #  denoting a new PID
          if "A." in line:
            summary = ""
          line = ""
        # END WHILE

        # PS, figuring this out was a pain, and it looks like
        #  I no longer need it anyway
        #line_iter = itertools.chain([line],line_iter)

    except StopIteration: 
      return pid_fields


if __name__ == "__main__":

  ## THIS SECTION IS ONLY FOR TESTING ##
  def check2(seq):
    """ Used here just for my own sanity checking """
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

  handled_special = [194,254]
  handled_special.extend([196,198,199,237,233,240,498,506,212,210,211,226])
  #doc = get_document_object("samplejson.def")
  doc = get_document_object()

  # Things to test within doc structure
  #['xdev_sids', 'fmis', 'mids', 'sids_for_mids', 'pid_fields', 'pids']

  
  pid_fields = doc["pid_fields"]

  # Print which multi-byte PID sequences still need addressing
  for x in pid_fields:
    bseq = pid_fields[x]["Sequence"]
    bseq = bseq.replace("(","").replace(")","")
    if not re.match("^[a-z]+$",bseq):
      if int(x) in handled_special: continue
      elif re.match("[a-z]+[a-z]1[a-z]2[a-z]3[a-z]4",bseq):
        continue
      elif "NodataassociatedwithPID" in bseq: 
        continue
      elif re.match("([a-z],)+[a-z]/[a-z],",bseq):
        continue
      # Grabs alternates
      # Seems to be too far reaching
      # nababab...
      elif re.match(".*(?P<n>([a-z])[^\1])(?P=n)",bseq) and "..." in bseq:
        continue
      # nabccdd...
      elif re.match(".*((?P<n>[a-z])(?P=n){1})+?",bseq) and check2(bseq) and "..." in bseq: 
        continue
      # Print the special cases to be handled for multi-byte PIDs
      print(x,pid_fields[x]["Sequence"])

  # Interesting ones to look at
  #dbg(pid_fields["204"])
  #dbg(pid_fields["219"])
  #dbg(pid_fields["226"])
  #dbg(pid_fields["192"])
  #dbg(pid_fields["500"])
  #dbg(pid_fields["450"])
  #dbg(pid_fields["223"])
  dbg(doc["sids_for_mids"])
 

