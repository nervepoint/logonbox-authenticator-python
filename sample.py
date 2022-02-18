import lba.client
import logging

logger = logging.getLogger('lba')
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())

client = lba.client.AuthenticatorClient('corp.logonbox.directory', logger=logger);
auth_response = client.authenticate('brett@logonbox.com');
success = auth_response.verify();
print("Success: %s" % success)