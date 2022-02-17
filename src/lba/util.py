'''
Primary class. 
'''

import io
import struct

class ByteArrayWriter:
    
    def __init__(self):
        self.file = io.BytesIO()
        
    def write_big_integer(self, val):
        a = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
        self.write_int(len(a))
        self.file.write(a)
        
    def write_int(self, val):
        self.file.write(val.to_bytes(32, byteorder='big'))
        
    def write_string(self, s, charset = 'UTF-8'):
        if(s == None):
            self.write_int(0)
        else:
            a = s.encode(charset)
            self.write_int(len(a))
            self.file.write(a)
        
    def write_binary_string(self, data):
        self.file.write(data)

class ByteArrayReader:
    
    def __init__(self, data):
        self.file = io.BytesIO(data)
        
    def read_int(self):
        return struct.unpack('>i', self.file.read(4))[0]
        
    def read_string(self):
        a = bytearray(self.read_int())
        self.file.readinto(a)
        return bytes(a).decode('UTF-8')
        
    def read_big_integer(self):
        return int.from_bytes(self.file.read(self.read_int()), byteorder='big')
        
    def read_binary_string(self):
        return self.file.read(self.read_int())
    
    def read_boolean(self):
        return self.file.read(1) == 1
        
        