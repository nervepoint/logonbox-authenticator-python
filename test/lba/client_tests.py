import unittest

import lba.client;
import base64

class EmptyRandomGenerator(lba.client.RandomGenerator):
    
    def bytes(self, count):
        return bytes(count)
    
class SequentialRandomGenerator(lba.client.RandomGenerator):
    
    def __init__(self):
        self.v = 1
        
    def bytes(self, count):
        b = bytearray(count)
        for i in range(0, count):
            b[i] = self.v
            self.v += 1
            if self.v == 256:
                self.v = 1
        return bytes(b)

class TestSignatureGenerator(lba.client.SignatureGenerator):
    
    def __init__(self, sig):
        self.sig = sig
    
    def request_signature(self, client, principal, fingerprint, text, button_text, encoded_payload, flags):
        return self.sig
    
class TestKeySource(lba.client.KeySource):
    def list_keys(self, client, principal):
        return [
            'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0ISnrIwtSbFr9oRTZNHJfaWcHH7xYKeCRJx8O3N+7+ LogonBox Key',
            'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDbu8Ihw4x/B6+V/1W7IRNb08cF7VoAm/4kdwi8ltnu7VrfKxXt6zeKg/x27MkJoy8ei051f797iamoPrNPdrh3E6nfRJoZda9ybqoOFFxunkk5ezT1V/Ai57iZunLyYxmDJfAdz3Ul8jTbMVjQusFV8rCacLBRa9t+hc5cErKcsRqYvVEpHuJYRnsApLBpW6bdqZ+jXiiRe17KW/aWq530ZlbsNhyN0jHalWpOxOiuFELVsO+TUGborY4wekyhwe5AWi29tqKj2p67ApFUDv6x8Y71pYLxfF4XrDD8ydGgFRES3sa+IogaTqN/PZgfamKQ+3DNW/SKpxdc0jzlBtX0V+E3q49a6t8k9277YnkDkTSFUYCUepPX5+Kjs4X0+dFTOFhO9fOCm7WDOesW6UPN0NIpndDUSY5654B8qqzW57/Nw7AQOVwzSvqrhP6yJS7qL2uZ8rN4UrjD4IY9T3QirZmq3ZBAeCuAdZ4+mcPgcv4eoXBQqGcC14J4q0MZrFs= Legacy RSA'
            ]

class AuthenticatorRequestTest(unittest.TestCase):
    
    def test_url_443(self):
        req = lba.client.AuthenticatorRequest(lba.client.AuthenticatorClient('test.mydomain.com'), 'KX1YIKPRkmHggrCC6KB90CuyNVsl2QO8ddgkgCruZIijgn1xxr0Wxnt8bURKbF0B8j8Af1aXW');
        self.assertEqual('https://test.mydomain.com/authenticator/sign/KX1YIKPRkmHggrCC6KB90CuyNVsl2QO8ddgkgCruZIijgn1xxr0Wxnt8bURKbF0B8j8Af1aXW', req.get_url());
    
    def test_url_8443(self):
        req = lba.client.AuthenticatorRequest(lba.client.AuthenticatorClient('test.mydomain.com', 8443), 'KX1YIKPRkmHggrCC6KB90CuyNVsl2QO8ddgkgCruZIijgn1xxr0Wxnt8bURKbF0B8j8Af1aXW');
        self.assertEqual("https://test.mydomain.com:8443/authenticator/sign/KX1YIKPRkmHggrCC6KB90CuyNVsl2QO8ddgkgCruZIijgn1xxr0Wxnt8bURKbF0B8j8Af1aXW", req.get_url());

class AuthenticatorClientTest(unittest.TestCase):
    
    def test_create_1(self):
        client = lba.client.AuthenticatorClient('test.mydomain.com')
        self.assertEqual(443, client.signature_generator.get_port())
        self.assertEqual("test.mydomain.com", client.signature_generator.get_hostname())
    
    def test_create_2(self):
        client = lba.client.AuthenticatorClient('test.mydomain.com', 8443)
        self.assertEqual(8443, client.signature_generator.get_port())
        self.assertEqual('test.mydomain.com', client.signature_generator.get_hostname())
        
    def test_other_constructor_args(self):
        client = lba.client.AuthenticatorClient('test.mydomain.com', authorize_text='Some authorize text', prompt_text='Some prompt text', remote_name='A remote name')
        self.assertEqual('Some authorize text', client.authorize_text)
        self.assertEqual('Some prompt text', client.prompt_text)
        self.assertEqual('A remote name', client.remote_name)
        
    def test_rsa_zero_random_bytes(self):
        client = lba.client.AuthenticatorClient(key_source = TestKeySource(),
                                    signature_generator = TestSignatureGenerator(base64.b64decode('qoeING0vzEXTjmFrX4ZQw2AfZJhFloL6ctgUZ8iveoyoV79V5R7cBfjhVJUDuvTwIqmVtFbcj3o76MNL4cj9tEGDWxgoNf/H0Kw55k08/QW/98VDX9eXxr/gDqDjMmWTnYPlqssqq/IR/OA08dNIZMoH1Wd3G+DCszrOr07lwyPC4oSISqs84fxlBJfaO6CpHncu6JJPyhjRis3Y1DH+t8MR3gCgMz0cl01KoXcYzwYY5kTe1qSpU3G8wtfhf6gGq6cIIu6mbsP6AXSvfiJ/XVB636g2oi2e33EaXzvh2fNHi6F6mVgJvT9Biu9fbzlcs3Q5LXbOFsm5u4NRcvSZY7YRNdJAwTwgS8E9lesPt3ME4iyIlpMa1Dy+sYlKPH1G6Guigi4zt4mRAJPASWG4yUxzeOgNAz8DCT9n0t2bMgst/AV3w8GvE2wC6igA/aJnYTiq+alwB2zUCjLMBSai1Q8hsvpsYDXUq2KgCvurLB781mvJO9MKWhWD51IVPeLT')),
                                    random_generator = EmptyRandomGenerator(),
                                    debug = True,
                                    ed25519 = False)
        self.assertTrue(client.authenticate('test').verify())
        
    def test_rsa_sequential_bytes(self):
        client = lba.client.AuthenticatorClient(key_source = TestKeySource(),
                                    signature_generator = TestSignatureGenerator(base64.b64decode('FcYTC3MqvhBeWZimEclN6c1ERnYdPOfWL7Uc3gGUybs+3wIow1rZ0/mH9c4VJ2IkwgdEDspmyppoGge8JMPrFf5zxsqQzJiUzqKFQDFOe3HcSRwjJk3OM8KFaQTymHubWsCiRQCGoiUuMd+7ETF6uANad3bT6fbAWiAPjhxJSwKP4udihMXhznuNfK7llNZT9t5EdMIiS4Xp7jh4L7ZddBINTR/O/fSBRk4HAppR5yJanEnHk7pfYjRxji+7jvtwx0nDAIhgkubsnelNGTgy1zDbHGt2cBS47XSMcyzN6xChFPHCN8b6J78mEP8vCjFCZReoAckzQqelbzBoKoneS/zDmqJqNeV21RfHCKApeZ877ZW0v54B4tHNeeWGFj7nbs8PzAe8UQAAU9jZyyQIi1qYZWKK7vtqhz3OurTqGvLSrFiVGOBV3rzguqbF+Tf4a4YCUhyg+AAW266yS/vB2aVxka+SQ6fNKAnDbiFxRRCzUT5sZl+XBSg7IS/TSwVU')),
                                    random_generator = SequentialRandomGenerator(),
                                    debug = True,
                                    ed25519 = False)
        self.assertTrue(client.authenticate('test').verify())
        
    def test_rsa_fail_sequential_bytes(self):
        client = lba.client.AuthenticatorClient(key_source = TestKeySource(),
                                    signature_generator = TestSignatureGenerator(SequentialRandomGenerator().bytes(384)),
                                    random_generator = SequentialRandomGenerator(),
                                    debug = True,
                                    ed25519 = False)
        self.assertFalse(client.authenticate('test').verify())
        
    def test_ed25519_zero_random_bytes(self):
        client = lba.client.AuthenticatorClient(key_source = TestKeySource(),
                                    signature_generator = TestSignatureGenerator(base64.b64decode('ZCqTWvzwzOimDwBGpsxgYzhVcJfWMCbF0D00lxFOfg4Z3777zWqq3iTvQgqiPKIaRVYOQ6vN9DvbxZiJOyyTAg==')),
                                    random_generator = EmptyRandomGenerator(),
                                    debug = True,
                                    rsa = False)
        self.assertTrue(client.authenticate('test').verify())
        
    def test_ed25519_sequential_bytes(self):
        client = lba.client.AuthenticatorClient(key_source = TestKeySource(),
                                    signature_generator = TestSignatureGenerator(base64.b64decode('1eB+ogdIs4G/+KvZBNI1Gzh6tQNsHn5BsFiDUhMPr3igf2Pnnm6bwRWlUlXYFUmi4LEr1mR9Jvc/5QUA9zm/CQ==')),
                                    random_generator = SequentialRandomGenerator(),
                                    debug = True,
                                    rsa = False)
        self.assertTrue(client.authenticate('test').verify())