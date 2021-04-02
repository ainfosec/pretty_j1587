import unittest as ut
import struct_from_J1587 as j1587
import pretty_j1587 as parser
from contextlib import contextmanager
from StringIO import StringIO
import sys, json, logging

@contextmanager
def captured_output():
    # This is pretty slick, I didn't come up with it myself
    # https://stackoverflow.com/questions/4219717/how-to-assert-output-with-nosetest-unittest-in-python/31281467
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err

class J1587TestClass(ut.TestCase):
  @classmethod
  def setUpClass(cls):
    parser.doc = j1587.get_document_object(customdb=False,nocache=True)
  @classmethod
  def tearDownClass(cls):
    pass
  def setUp(self): 
    parser.whitelist = []
    parser.canon_function = False
    parser.pregular = True
    parser.verbosity = 0
    parser.do_json = False
    parser.pdelim = True
    parser.formatt = False
    parser.checksums = False
    parser.l = logging.getLogger("pretty_1587")
    parser.whitelist_print = False 
  def tearDown(self): 
    pass
  def test_pid_194_bytecount(self): 
    bytecount = j1587.get_bytecount_from_pid(194)
    self.assertTrue(bytecount == 3)
  def test_import_worked(self):
    self.assertTrue(parser)
  def test_whitelist_exists(self):
    self.assertTrue(isinstance(parser.whitelist,list))
  def test_whitelist(self):
    msg= "0x89,0x30,0x33"
    parser.whitelist = [0x30]
    with captured_output() as (sout,serr): 
      parser.parse_message(msg)
    self.assertTrue("PID 0x30" in sout.getvalue())
  def test_not_whitelist(self):
    msg= "0x89,0x30,0x33"
    parser.whitelist = [0x39]
    with captured_output() as (sout,serr): 
      parser.parse_message(msg)
    out = sout.getvalue().strip()
    self.assertFalse("PID 0x39" in out)
    self.assertFalse("MID 0x89" in out)
  def test_json(self):
    parser.do_json = True
    parser.pdelim = False
    parser.pregular = False
    msg= "0x89,0x30,0x33"
    with captured_output() as (sout,serr): 
      parser.parse_message(msg)
    jmsg = json.loads(sout.getvalue().strip())
    self.assertTrue("PID_DEF" in jmsg["DATA"][str(0x30)])
  def test_json_checksum(self):
    parser.do_json = True
    parser.pdelim = False
    parser.pregular = False
    parser.checksums = True
    msg= "0x89,0x30,0x33,0x2d"
    with captured_output() as (sout,serr): 
      parser.parse_message(msg)
    jmsg = json.loads(sout.getvalue().strip())
    self.assertTrue("CLC_CHECKSUM" in jmsg)
    self.assertTrue(jmsg["CLC_CHECKSUM"] == 20)
  def test_special_pid_var_len(self):
    msg="87,d3,02,c2,c1,d3,01,c2,c0,bf,cf,df"
    with captured_output() as (sout,serr):
      parser.parse_message(msg)
    self.assertTrue(sout.getvalue().strip().count("PID 0xd3") == 2)
  def test_J1708(self):
    msg="17,0a,0a,0a"
    with captured_output() as (sout,serr): 
      parser.parse_message(msg)
    self.assertTrue("TRANSMISSION" in sout.getvalue().strip()) 
    
if __name__ == "__main__":
  ut.main()
