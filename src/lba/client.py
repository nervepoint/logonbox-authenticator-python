'''
'''

import base64
import secrets
import urllib.request
import urllib.parse
import hashlib
import json
import time

from .util import ByteArrayReader
from .util import ByteArrayWriter
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA, SHA512, SHA256
from dns.dnssec import _is_rsa

def _is_rsa(key):
    return isinstance(key, RSA._RSAobj)    

def _is_ed25519(key):
    raise('Unsupported') # TODO

def _is_eddsa(key):
    raise('Unsupported') # TODO

class AuthenticatorResponse:
    
    def __init__(self, key, payload, signature, flags):
        self.key = key
        self.payload = payload
        self.signature = signature
        self.flags = flags
        
    def verify(self):
        if _is_rsa(self.key):
            self._verify_rsa_signature()
        elif _is_ed25519(self.key):
            self._verify_ed25519_signature()
        elif _is_eddsa(self.key):
            self._verify_eddsa_signature()
        else:
            raise('Unsupported key type')
    
    def _verify_rsa_signature(self):
        v = PKCS1_v1_5.new(self.key)
        h = None
        if self.flags == 4:
            h = SHA512.new(self.payload)
        elif self.flags == 2:
            h = SHA256.new(self.payload)
        else:
            h = SHA.new(self.payload)
        v.verify(h, self.signature)
    
    def _verify_ed25519_signature(self):
        raise('Unsupported') # TODO
    
    def _verify_eddsa_signature(self):
        raise('Unsupported') # TODO
    
class AuthenticatorRequest:
    
    def __init__(self, client, encoded_payload):
        self.client = client
        self.encoded_payload = encoded_payload
        
    def get_url(self):
        if self.client.port == 443:
            return 'https://%s/authenticator/sign/%s' % (self.client.host, self.encoded_payload)
        else:
            return 'https://%s:%d/authenticator/sign/%s' % (self.client.host, self.client.port, self.encoded_payload)
        
    def process_response(self, response):
        return self.client.process_response(base64.urlsafe_b64decode(self.encoded_payload), base64.urlsafe_b64decode(response))

class AuthenticatorClient:
    
    ED25519_ASN_HEADER = bytes([0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00])
    
    def __init__(self, host, port = 443, 
                 remote_name = 'LogonBox Authenticator API',
                 prompt_text = '{username} wants to authenticate from {remoteName} using your {hostname} credentials.',
                 authorize_text = 'Authorize',
                 logger = None):
        
        self.host = host
        self.port = port
        self.remote_name = remote_name
        self.prompt_text = prompt_text
        self.authorize_text = authorize_text
        self.logger = logger
        
    def authenticate(self, principal, payload = secrets.token_bytes(256)):
        with urllib.request.urlopen('https://%s:%d/authorizedKeys/%s' % (self.host, self.port, principal)) as response:
            body = response.read()
            if self.logger != None:
                self.logger.info('Received authorized keys from %s', self.host);
                self.logger.info(body);
            
            it = iter(body.splitlines())
            if not next(it).decode('UTF-8').startswith('# Authorized'):
                raise Exception('Unable to list users authorized keys from %s', self.host)
            for k in it:
                k = k.decode('UTF-8')
                if k.startswith('#'):
                    continue
                else:
                    try:
                        if self.logger != None:
                            self.logger.info('Parsing key %s', k);
                
                        pub = self._decode_key(k)
                        
                        if self.logger != None:
                            self.logger.info('Decoded %s public key', self._get_algorithm(pub));
                            
                        return self._sign_payload(principal, pub, self._replace_variables(self.prompt_text, principal), self.authorize_text, payload)
                    except Exception:
                        if self.logger != None:
                            self.logger.warn('Failed %s public key', k, exc_info = True);
                        continue
                    
            raise Exception('No suitable key found for %s' % principal)
        
    def get_user_keys(self, principal):
        l = []
        with urllib.request.urlopen('https://%s:%d/authorizedKeys/%s' % (self.host, self.port, principal)) as response:
            body = response.read()
            if self.logger != None:
                self.logger.info('Received authorized keys from %s', self.host);
                self.logger.info(' "%s"', body.decode('UTF-8'));
                
            it = iter(body.splitlines())
            if not next(it).decode('UTF-8').startswith('# Authorized'):
                raise Exception('Unable to list users authorized keys from %s' % self.host)
            for k in it:
                k = k.decode('UTF-8')
                if k.startswith('#'):
                    continue
                else:
                    try:
                        if self.logger != None:
                            self.logger.info('Parsing key %s', k);
                        pub = self._decode_key(k)
                        
                        if self.logger != None:
                            self.logger.info('Decoded %s public key', self._get_algorithm(pub));
                        l.append(pub)
                    except:
                        if self.logger != None:
                            self.logger.warn('Failed %s public key', k, exc_info = True);
                        continue
        return l
    
    def generate_request(self, email, redirect_url):
        w = ByteArrayWriter()
        key = self.get_default_key(email)
        fingerprint = self._generate_fingerprint(key)
        flags = self.get_flags(key)
        w.write_string(email)
        w.write_string(fingerprint)
        w.write_string(self.remote_name)
        w.write_string(self.prompt_text)
        w.write_string(self.authorize_text)
        w.write_int(flags)
        w.write_int(round(time.time() * 1000))
        w.write_string(redirect_url)
        
        return AuthenticatorRequest(self, base64.urlsafe_b64encode(w.get_bytes()))
    
    def process_response(self, payload, sig):
        r = ByteArrayReader(sig)
        if r.read_boolean():
            username = r.read_string()
            fingerprint = r.read_string()
            flags = r.read_int()
            signature = r.read_string()
            return AuthenticatorResponse(self.get_user_key(username, fingerprint), payload, signature, flags)
        else:
            raise Exception(r.read_string())
        
    def get_flags(self, key):
        if _is_rsa(key):
            return 4
        else:
            return 0
        
    def get_default_key(self, email):
        keys = self.get_user_keys(email);
        selected = None
        for key in keys:
            if _is_rsa(key):
                selected = key
                break
        
        if selected == None and len(keys) > 0:
            selected = keys[0]
        
        return selected
    
    def _replace_variables(self, prompt_text, principal):
        return prompt_text.replace('{username}', principal).replace('{remoteName}', self.remote_name).replace('{hostname}', self.host)
    
    def _sign_payload(self, principal, key, text, button_text, payload):
        fingerprint = self._generate_fingerprint(key)
        
        if self.logger != None:
            self.logger.info('Key fingerprint is %s', fingerprint);
        
        encoded_payload = base64.urlsafe_b64encode(payload)
        flags = 0
        
        if isinstance(key, RSA._RSAobj):
            # Tell the server we want a RSAWithSHA512 signature
            flags = 4

        return AuthenticatorResponse(key, payload, self._request_signature(principal, fingerprint, text, button_text, encoded_payload, flags), flags)
    
    def _get_algorithm(self, key):
        if _is_rsa(key):
            return 'ssh-rsa'
        else:
            raise Exception('Unsupported') # TODO
        
    def _encode_key(self, key):
        w = ByteArrayWriter()
        a = self._get_algorithm(key)
        w.write_string(a)
        if a == 'ssh-rsa':
            w.write_big_integer(key.e)
            w.write_big_integer(key.n)
        else:
            raise('Unsupported') # TODO
        
        return w.get_bytes()
    
    def _generate_fingerprint(self, key):
        m = hashlib.sha256()
        m.update(self._encode_key(key))
        digest = m.digest()
        buf = 'SHA256:'
        buf += base64.b64encode(digest).decode('UTF-8')
        while buf.endswith('='):
            buf = buf[:-1]
        return buf
    
    def _request_signature(self, principal, fingerprint, text, button_text, encoded_payload, flags):
        data = urllib.parse.urlencode({
            'username': principal,
            'fingerprint' : fingerprint,
            'remoteName' : self.remote_name,
            'text' : text,
            'authorizeText' : button_text,
            'flags' : flags,
            'payload' : encoded_payload
        }) 
        
        if self.logger != None:
            self.logger.info('Request data "%s"', data)
                
        req = urllib.request.Request('https://%s:%d/app/api/authenticator/signPayload' % (self.host, self.port), data = data.encode('UTF-8'), headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        with urllib.request.urlopen(req) as response:
            body = response.read()
            
            if self.logger != None:
                self.logger.info('Received %d response', response.getcode())
                self.logger.info(body)
            
            if response.getcode() != 200:
                raise Exception('Expected response with code 200')
                
            sigresponse = json.loads(body)
            if sigresponse['success'] != True:
                raise Exception(sigresponse['message'])
            
            if sigresponse['signature'] == '':
                r = ByteArrayReader(base64.urlsafe_b64decode(sigresponse['response']))
                if not r.read_boolean():
                    raise Exception('No signature. %s' % r.read_string())
                raise Exception('The server did not respond with a valid response!');
            
            return base64.urlsafe_b64decode(sigresponse['signature'])

    def _decode_key(self, keystr):
        
        idx = keystr.index(' ')
        idx2 = keystr.index(' ' , idx + 1)
        
        encoded = keystr[idx + 1: idx2]
        
        r = ByteArrayReader(base64.b64decode(encoded))
        algo = r.read_string()
        
        if self.logger != None:
            self.logger.info('Key "%s" is a %s',keystr, algo)
        
        if algo == 'ssh-rsa':
            return self._decode_rsa(r)
        elif algo == 'ssh-ed25519':
            return self._decode_ed25519(r)
        else:
            raise Exception('Unknown key type %s', algo)
        
    def _decode_rsa(self, reader):
        e = reader.read_big_integer()
        n = reader.read_big_integer()
        return RSA.construct((n, e)).publickey()
        
    def _decode_ed25519(self, reader):
        raise Exception('Unsupported') # TODO
        
        
        