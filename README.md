# LogonBox Authenticator API for Python

Use this API to integrate LogonBox Authenticator into your own Python application authentication flows.  

The LogonBox Authenticator uses an authentication mechanism similar to SSH private key authentication where users keys are published in an authorized keys listing on the credential server. This API will read the trusted public keys and then submit an authentication request payload to the credential server for signing by the corresponding private key. 

As part of the signing operation, the user must authorize the request within the LogonBox Authenticator app. Once authorized the payload is signed by the private key, which is held exclusively within the secure storage of the app. 

To authenticate the user, the API verifies the signature returned to obtain the authentication result.

# About LogonBox Authenticator

Safeguard your people, passwords and apps with LogonBox's 2-Factor [Authentication app](https://www.logonbox.com/content/logonbox-authenticator/) for Android and iOS. 

<img src="web/logonbox-logo.png" width="256">

## Other Languages

 * [Java](https://github.com/nervepoint/logonbox-authenticator-java)
 * [Node/Javascript](https://github.com/nervepoint/logonbox-authenticator-nodejs)
 * [PHP](https://github.com/nervepoint/logonbox-authenticator-php)

# Requirements

 * Python 3
 * [PyCryptodome](https://pypi.org/project/pycryptodome/)
 * [python-ed25519](https://github.com/warner/python-ed25519)

## Usage

There are many ways the authenticator can be used and this will depend on your authentication use case. 

### Server Redirect

If you are logging a user into a web application, you can create a request, and redirect the user to a URL on the credential server where they are prompted to authorize the request on their device. This eliminates the need for you to create your own user interface and provides a modern, clean authentication flow. 

When authentication completes, the server redirects back to your web application with an authentication response which you pass into the API for verification. 

The below example, assumes you are using Django framework. Adjust storage of session attributes and
redirect to your framework.

#### Generate a Request and Redirect to the Credential Server
```python
# Create a client and configure it with the LogonBox server

import lba.client

def authenticator_start(request):
	client = lba.client.AuthenticatorClient('tenant.logonbox.directory');
	
	# Generate a request passing a URL for the redirect back to your webapp.
	# Note how {response} is used to place the servers response into the redirected URL
	
	auth_request = client.generate_request(username,
	    'https://localhost/authenticator_finish?response={response}');
	
	# Save the request so it can be picked up when we receive the response
	request.session['auth_request'], auth_request);
	
	# Now redirect the user to the URL provided by the AuthenticationRequest
	return redirect(auth_request.get_url());
```

#### Process the response
```python
def authenticator_finish(request):
	# Grab the authenticator request out of the HTTP session
	auth_request = request.session.get('auth_request')
	
	# Get the servers response from the URL parameters
	response = request.GET.get('response');
	
	# Pass the response into the authenticator request to get the response. **/
	auth_response = auth_request.process_response(response);
				
	# Verify the response
	if resp.verify():
	    # The user has authenticated, do stuff ..
```


### Direct Signing

If you are using a different protocol and cannot redirect the user via a web browser, or want to provide your own user interface, you can perform authentication exclusively through the API. 

```python
# Create a client and configure it with the LogonBox server
client = lba.client.AuthenticatorClient('tenant.logonbox.directory');

# Send the request, and receive the signed response. 
# The user will receive an authentication prompt on this call.
auth_response = client.authenticate('lee@logonbox.com');
	
# Call verify on the response to validate the authentication. 
#Only allowing access to your application when a true value has been returned.
success = resp.verify();
```

## Debugging

You can pass a `logger=....` argument into the `lba.client.Client` constructor. Whatever object you pass into should support a `info(<format>, <arg1>, <arg2>, ..)` function, as well as an `error(..)` function with the same signature. For convenience, you can pass in a standard Python logger object here.

```python
import logging
client = lba.client.Client('tenant.logonbox.directory', logger=logging.getLogger('my-logger'));
```
