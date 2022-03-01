#!/usr/bin/env python

import lba.client

client = lba.client.AuthenticatorClient('corp.logonbox.directory', debug=True, ed25519=False)
auth_response = client.authenticate('brett@logonbox.com')
if auth_response.verify():
    print("Success!")
else:
    print("Failure!")