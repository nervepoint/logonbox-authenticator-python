import unittest

import lba.util;

class ByteArrayWriterTest(unittest.TestCase):
    
    def test_write_string(self):
        w = lba.util.ByteArrayWriter();
        w.write_string("A Test String");
        self.assertEqual(bytes([  0,  0,  0,  13,  65,  32,  84, 101,  115,  116,  32,  83,  116,  114,  105, 110,  103 ]), w.get_bytes());
        
    def test_integer(self):
        w = lba.util.ByteArrayWriter()
        w.write_int(4294967295)
        w.write_int(0)
        w.write_int(255)
        w.write_int(4294967040)
        self.assertEqual(bytes([  0xff,  0xff,  0xff,  0xff, 0, 0, 0, 0, 0, 0, 0, 0xff,  0xff,  0xff,  0xff, 0 ]), w.get_bytes())

    def test_big_integer(self):
        w = lba.util.ByteArrayWriter();
        w.write_big_integer(329802389981797891243908975290812);
        self.assertEqual(bytes([  0,  0,  0,  14,  16,  66,  176, 254,  247,  114,  215,  130,  240,  27,  237, 39,  233,  188 ]), w.get_bytes());

    def test_binary_string(self):
        w = lba.util.ByteArrayWriter()
        w.write_binary_string("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".encode('UTF-8'))
        self.assertEqual(bytes([  0,  0,  0,  123,  76,  111,  114,  101,
                         109,  32,  105,  112,  115,  117,  109,  32,
                         100,  111,  108,  111,  114,  32,  115,  105,
                         116,  32,  97,  109,  101,  116,  44,  32,
                         99,  111,  110,  115,  101,  99,  116,  101,
                         116,  117,  114,  32,  97,  100,  105,  112,
                         105,  115,  99,  105,  110,  103,  32,  101,
                         108,  105,  116,  44,  32,  115,  101,  100,
                         32,  100,  111,  32,  101,  105,  117,  115,
                         109,  111,  100,  32,  116,  101,  109,  112,
                         111,  114,  32,  105,  110,  99,  105,  100,
                         105,  100,  117,  110,  116,  32,  117,  116,
                         32,  108,  97,  98,  111,  114,  101,  32,
                         101,  116,  32,  100,  111,  108,  111,  114,
                         101,  32,  109,  97,  103,  110,  97,  32,
                         97,  108,  105,  113,  117,  97,  46 ]),
                w.get_bytes())

class ByteArrayReaderTest(unittest.TestCase):

    def test_read_string(self):
        r = lba.util.ByteArrayReader(bytes([ 0,  0,  0,  13,  65,  32, 84,  101,  115,  116,  32,  83,  116,  114,  105, 110,  103]))
        self.assertEqual("A Test String", r.read_string())

    def test_integer(self):
        r = lba.util.ByteArrayReader(bytes([  0xff,  0xff,  0xff,  0xff, 0, 0, 0, 0, 0, 0, 0,  0xff,  0xff,  0xff,  0xff, 0 ]));
        self.assertEqual(4294967295, r.read_int())
        self.assertEqual(0, r.read_int())
        self.assertEqual(255, r.read_int())
        self.assertEqual(4294967040, r.read_int())

    def test_binary_string(self):
        r = lba.util.ByteArrayReader(bytes([  0,  0,  0,  123,  76,  111,
                 114,  101,  109,  32,  105,  112,  115,  117,
                 109,  32,  100,  111,  108,  111,  114,  32,
                 115,  105,  116,  32,  97,  109,  101,  116,  44,
                 32,  99,  111,  110,  115,  101,  99,  116,  101,
                 116,  117,  114,  32,  97,  100,  105,  112,
                 105,  115,  99,  105,  110,  103,  32,  101, 
                 108,  105,  116,  44,  32,  115,  101,  100,  32,
                 100,  111,  32,  101,  105,  117,  115,  109,
                 111,  100,  32,  116,  101,  109,  112,  111,
                 114,  32,  105,  110,  99,  105,  100,  105,
                 100,  117,  110,  116,  32,  117,  116,  32,
                 108,  97,  98,  111,  114,  101,  32,  101,  116,
                 32,  100,  111,  108,  111,  114,  101,  32,
                 109,  97,  103,  110,  97,  32,  97,  108,  105,
                 113,  117,  97,  46 ]))

        self.assertEqual(
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.".encode("UTF-8"),
                r.read_binary_string())

    def test_big_integer(self):
        r = lba.util.ByteArrayReader(bytes([   0,  0,  0,  14,  16,  66,
                 176,  254,  247,  114,  215,  130,  240,  27,
                 237,  39,  233,  188 ]))
        self.assertEqual(329802389981797891243908975290812, r.read_big_integer())

    def test_boolean(self):
        r = lba.util.ByteArrayReader(bytes([ 0, 1 ]))
        self.assertFalse(r.read_boolean())        
        self.assertTrue(r.read_boolean())
