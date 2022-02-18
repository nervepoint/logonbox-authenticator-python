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
        
    def test_massive_integer(self):
        w = lba.util.ByteArrayWriter()
        w.write_big_integer(4986580695048258251352289243969528543723799114324057371323608612564101467693190796478532220284311403189255873250803291602531019677110835331481798144386049284511688009328775687804730487000620487321119382781090544960120583643153599562724683545896843186364280959049341308629380720692043569110468202632021048673338887960542310457475382130231373634793736853819191982436405235215379401298185584213567077387840129057385674664071727417723315763120148348448625747824864998778650276874067046964948041454108472270884726573176720890632226924444526896411492224011080798782446878497167945815843132905198949069567082142592104355525279386692616234048604119115967592552701346081832583566701136596353331815241580453022478423878876764704414366376336598553049072822810090907768245535476110588270567353835663980833082822835527392197580869451516391575655964243632587493986489280683147080083155190055556030197814111481606633955453576346428985945179);
        self.assertEqual(bytes([ 0, 0, 1, 129, 0, 219, 187,
                194, 33, 195, 140, 127, 7, 175, 149, 255,
                85, 187, 33, 19, 91, 211, 199, 5, 237,
                90, 0, 155, 254, 36, 119, 8, 188, 150,
                217, 238, 237, 90, 223, 43, 21, 237, 235,
                55, 138, 131, 252, 118, 236, 201, 9, 163,
                47, 30, 139, 78, 117, 127, 191, 123, 137,
                169, 168, 62, 179, 79, 118, 184, 119, 19,
                169, 223, 68, 154, 25, 117, 175, 114,
                110, 170, 14, 20, 92, 110, 158, 73, 57,
                123, 52, 245, 87, 240, 34, 231, 184, 153,
                186, 114, 242, 99, 25, 131, 37, 240, 29,
                207, 117, 37, 242, 52, 219, 49, 88, 208,
                186, 193, 85, 242, 176, 154, 112, 176,
                81, 107, 219, 126, 133, 206, 92, 18, 178,
                156, 177, 26, 152, 189, 81, 41, 30, 226,
                88, 70, 123, 0, 164, 176, 105, 91, 166,
                221, 169, 159, 163, 94, 40, 145, 123, 94,
                202, 91, 246, 150, 171, 157, 244, 102,
                86, 236, 54, 28, 141, 210, 49, 218, 149,
                106, 78, 196, 232, 174, 20, 66, 213, 176,
                239, 147, 80, 102, 232, 173, 142, 48,
                122, 76, 161, 193, 238, 64, 90, 45, 189,
                182, 162, 163, 218, 158, 187, 2, 145, 84,
                14, 254, 177, 241, 142, 245, 165, 130,
                241, 124, 94, 23, 172, 48, 252, 201, 209,
                160, 21, 17, 18, 222, 198, 190, 34, 136,
                26, 78, 163, 127, 61, 152, 31, 106, 98,
                144, 251, 112, 205, 91, 244, 138, 167,
                23, 92, 210, 60, 229, 6, 213, 244, 87,
                225, 55, 171, 143, 90, 234, 223, 36, 247,
                110, 251, 98, 121, 3, 145, 52, 133, 81,
                128, 148, 122, 147, 215, 231, 226, 163,
                179, 133, 244, 249, 209, 83, 56, 88, 78,
                245, 243, 130, 155, 181, 131, 57, 235,
                22, 233, 67, 205, 208, 210, 41, 157, 208,
                212, 73, 142, 122, 231, 128, 124, 170,
                172, 214, 231, 191, 205, 195, 176, 16,
                57, 92, 51, 74, 250, 171, 132, 254, 178,
                37, 46, 234, 47, 107, 153, 242, 179, 120,
                82, 184, 195, 224, 134, 61, 79, 116, 34,
                173, 153, 170, 221, 144, 64, 120, 43,
                128, 117, 158, 62, 153, 195, 224, 114,
                254, 30, 161, 112, 80, 168, 103, 2, 215,
                130, 120, 171, 67, 25, 172, 91 ]), w.get_bytes())

    def test_sig(self):
        w = lba.util.ByteArrayWriter()
        w.write_string("ssh-rsa")
        w.write_big_integer(65537)
        w.write_big_integer(4986580695048258251352289243969528543723799114324057371323608612564101467693190796478532220284311403189255873250803291602531019677110835331481798144386049284511688009328775687804730487000620487321119382781090544960120583643153599562724683545896843186364280959049341308629380720692043569110468202632021048673338887960542310457475382130231373634793736853819191982436405235215379401298185584213567077387840129057385674664071727417723315763120148348448625747824864998778650276874067046964948041454108472270884726573176720890632226924444526896411492224011080798782446878497167945815843132905198949069567082142592104355525279386692616234048604119115967592552701346081832583566701136596353331815241580453022478423878876764704414366376336598553049072822810090907768245535476110588270567353835663980833082822835527392197580869451516391575655964243632587493986489280683147080083155190055556030197814111481606633955453576346428985945179);

        self.assertEqual(bytes([ 0, 0, 0, 7, 115, 115, 104, 45,
                114, 115, 97, 0, 0, 0, 3, 1, 0, 1,
                0, 0, 1, 129, 0, 219, 187, 194, 33,
                195, 140, 127, 7, 175, 149, 255, 85, 187,
                33, 19, 91, 211, 199, 5, 237, 90, 0,
                155, 254, 36, 119, 8, 188, 150, 217, 238,
                237, 90, 223, 43, 21, 237, 235, 55, 138,
                131, 252, 118, 236, 201, 9, 163, 47, 30,
                139, 78, 117, 127, 191, 123, 137, 169,
                168, 62, 179, 79, 118, 184, 119, 19, 169,
                223, 68, 154, 25, 117, 175, 114, 110,
                170, 14, 20, 92, 110, 158, 73, 57, 123,
                52, 245, 87, 240, 34, 231, 184, 153, 186,
                114, 242, 99, 25, 131, 37, 240, 29, 207,
                117, 37, 242, 52, 219, 49, 88, 208, 186,
                193, 85, 242, 176, 154, 112, 176, 81,
                107, 219, 126, 133, 206, 92, 18, 178,
                156, 177, 26, 152, 189, 81, 41, 30, 226,
                88, 70, 123, 0, 164, 176, 105, 91, 166,
                221, 169, 159, 163, 94, 40, 145, 123, 94,
                202, 91, 246, 150, 171, 157, 244, 102,
                86, 236, 54, 28, 141, 210, 49, 218, 149,
                106, 78, 196, 232, 174, 20, 66, 213, 176,
                239, 147, 80, 102, 232, 173, 142, 48,
                122, 76, 161, 193, 238, 64, 90, 45, 189,
                182, 162, 163, 218, 158, 187, 2, 145, 84,
                14, 254, 177, 241, 142, 245, 165, 130,
                241, 124, 94, 23, 172, 48, 252, 201, 209,
                160, 21, 17, 18, 222, 198, 190, 34, 136,
                26, 78, 163, 127, 61, 152, 31, 106, 98,
                144, 251, 112, 205, 91, 244, 138, 167,
                23, 92, 210, 60, 229, 6, 213, 244, 87,
                225, 55, 171, 143, 90, 234, 223, 36, 247,
                110, 251, 98, 121, 3, 145, 52, 133, 81,
                128, 148, 122, 147, 215, 231, 226, 163,
                179, 133, 244, 249, 209, 83, 56, 88, 78,
                245, 243, 130, 155, 181, 131, 57, 235,
                22, 233, 67, 205, 208, 210, 41, 157, 208,
                212, 73, 142, 122, 231, 128, 124, 170,
                172, 214, 231, 191, 205, 195, 176, 16,
                57, 92, 51, 74, 250, 171, 132, 254, 178,
                37, 46, 234, 47, 107, 153, 242, 179, 120,
                82, 184, 195, 224, 134, 61, 79, 116, 34,
                173, 153, 170, 221, 144, 64, 120, 43,
                128, 117, 158, 62, 153, 195, 224, 114,
                254, 30, 161, 112, 80, 168, 103, 2, 215,
                130, 120, 171, 67, 25, 172, 91 ]), w.get_bytes())

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
