import itertools
import multiprocessing.queues
import queue
import unittest as ut
from unittest.mock import patch, mock_open

from textwrap import dedent

import canon_functions
import struct_from_J1587 as j1587
import pretty_j1587 as parser
from contextlib import contextmanager
from io import StringIO
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
    parser.doc = j1587.get_document_object(customdb=False, nocache=True)

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
    self.message_queue = parser.PyHvNetworksTransportReassemblerQueue(suppress_fragments=True)

  def tearDown(self):
    self.message_queue.close()

  def fill_queue(self, messages):
    for message in messages:
      self.message_queue.put(parser.canonicalize(message))
    #self.message_queue.put(None)  # terminates the driver
    return

  def pretty_print_all(self):
    parser.pretty_print_all(self.message_queue)

  def test_pid_194_bytecount(self):
    bytecount = j1587.get_bytecount_from_pid(194)
    self.assertTrue(bytecount == 3)
  def test_import_worked(self):
    self.assertTrue(parser)
  def test_whitelist_exists(self):
    self.assertTrue(isinstance(parser.whitelist,list))
  def test_whitelist(self):
    self.fill_queue(["0x89,0x30,0x33"])
    parser.whitelist = [0x30]
    with captured_output() as (sout,serr):
      self.pretty_print_all()
    self.assertTrue("PID 0x30" in sout.getvalue())
  def test_not_whitelist(self):
    self.fill_queue(["0x89,0x30,0x33"])
    parser.whitelist = [0x39]
    with captured_output() as (sout,serr):
      self.pretty_print_all()
    out = sout.getvalue().strip()
    self.assertFalse("PID 0x39" in out)
    self.assertFalse("MID 0x89" in out)
  def test_json(self):
    parser.do_json = True
    parser.pdelim = False
    parser.pregular = False
    self.fill_queue(["0x89,0x30,0x33"])
    with captured_output() as (sout,serr):
      self.pretty_print_all()
    jmsg = json.loads(sout.getvalue().strip())
    self.assertTrue("PID_DEF" in jmsg["DATA"][str(0x30)])
  def test_json_checksum(self):
    parser.do_json = True
    parser.pdelim = False
    parser.pregular = False
    parser.checksums = True
    self.fill_queue(["0x89,0x30,0x33,0x2d"])
    with captured_output() as (sout,serr):
      self.pretty_print_all()
    jmsg = json.loads(sout.getvalue().strip())
    self.assertTrue("CLC_CHECKSUM" in jmsg)
    self.assertTrue(jmsg["CLC_CHECKSUM"] == 20)
  def test_special_pid_var_len(self):
    self.fill_queue(["87,d3,02,c2,c1,d3,01,c2,c0,bf,cf,df"])
    with captured_output() as (sout,serr):
      self.pretty_print_all()
    self.assertTrue(sout.getvalue().strip().count("PID 0xd3") == 2)
  def test_J1708(self):
    self.fill_queue(["17,0a,0a,0a"])
    with captured_output() as (sout,serr):
      self.pretty_print_all()
    self.assertTrue("TRANSMISSION" in sout.getvalue().strip())
  def test_reassemble(self):
    self.fill_queue(["ac,c5,05,80,01,01,0c,00",
                     "ac,c6,0e,80,01,00,c8,07,04,06,00,46,41,41,5a,05,48"])
    with captured_output() as (sout,serr):
      self.pretty_print_all()
    self.assertTrue("MSG: [0xac,0x0,0xc8,0x7,0x4,0x6,0x0,0x46,0x41,0x41,0x5a,0x5,0x48]" in sout.getvalue().strip())


TEST_LINE_DATA = dedent("""
    0x89,0x30,0x33
    0x89,0x30,0x33,0x2d
    87,d3,02,c2,c1,d3,01,c2,c0,bf,cf,df
    ac,c5,05,80,01,01,0c,00
    ac,c6,0e,80,01,00,c8,07,04,06,00,46,41,41,5a,05,48
    """).strip()


class FilesReceiver(ut.TestCase):
  @classmethod
  def setUpClass(cls):
    parser.doc = j1587.get_document_object(customdb=False, nocache=True)

  @classmethod
  def tearDownClass(cls):
    pass

  @patch("builtins.open", mock_open(read_data=TEST_LINE_DATA))
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

    self.message_queue = parser.PyHvNetworksTransportReassemblerQueue(suppress_fragments=True)
    self.files_thread = parser.FilesReceiver(["dne_dont_worry_its_patched"], self.message_queue)
    self.files_thread.start()

  def tearDown(self):
    self.message_queue.close()
    self.files_thread.join()

  def test_prettyprintall(self):
    with captured_output() as (sout,serr):
      parser.pretty_print_all(self.message_queue)
    self.assertTrue("PID 0x30" in sout.getvalue())
    self.assertTrue("MSG: [0xac,0x0,0xc8,0x7,0x4,0x6,0x0,0x46,0x41,0x41,0x5a,0x5,0x48]" in sout.getvalue().strip())


class TcpLineReceiver(ut.TestCase):
  @classmethod
  def setUpClass(cls):
    parser.doc = j1587.get_document_object(customdb=False, nocache=True)

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
    self.message_queue.close()

  @patch('socket.socket', autospec=True)
  def test_prettyprintall(self, mock_socket):
    mock_conn = ut.mock.Mock()
    mock_conn.recv.side_effect = itertools.chain([TEST_LINE_DATA.encode('utf-8')], itertools.repeat(None))
    mock_socket = mock_socket.return_value
    mock_socket.accept.return_value = (mock_conn, -1)
    ut.mock.patch('socket.socket', mock_socket)

    self.message_queue = parser.PyHvNetworksTransportReassemblerQueue(suppress_fragments=True)
    self.tcp_thread = parser.TcpLineReceiver(-1, self.message_queue)
    self.tcp_thread.start()

    with captured_output() as (sout,serr):
      parser.pretty_print_all(self.message_queue)
    self.assertTrue("PID 0x30" in sout.getvalue())
    self.assertTrue("MSG: [0xac,0x0,0xc8,0x7,0x4,0x6,0x0,0x46,0x41,0x41,0x5a,0x5,0x48]" in sout.getvalue().strip())


class UdpLineReceiver(ut.TestCase):
  @classmethod
  def setUpClass(cls):
    parser.doc = j1587.get_document_object(customdb=False, nocache=True)

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
    self.message_queue.close()

  @patch('socket.socket', autospec=True)
  def test_prettyprintall(self, mock_socket):
    mock_conn = ut.mock.Mock()
    mock_socket = mock_socket.return_value
    mock_socket.recv.side_effect = itertools.chain([TEST_LINE_DATA.encode('utf-8')], itertools.repeat(None))
    ut.mock.patch('socket.socket', mock_socket)

    self.message_queue = parser.PyHvNetworksTransportReassemblerQueue(suppress_fragments=True)
    self.udp_thread = parser.UdpLineReceiver(-1, self.message_queue)
    self.udp_thread.start()

    with captured_output() as (sout,serr):
      parser.pretty_print_all(self.message_queue)
    self.assertTrue("PID 0x30" in sout.getvalue())
    self.assertTrue("MSG: [0xac,0x0,0xc8,0x7,0x4,0x6,0x0,0x46,0x41,0x41,0x5a,0x5,0x48]" in sout.getvalue().strip())


if __name__ == "__main__":
  ut.main()
