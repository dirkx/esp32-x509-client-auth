Pairing protocol

#	Generate a self signed X509 certificate
#	(because of ESP32 limitations) - fetch the certificate chain of the server.
#	Do a get on /register?name=XXXX; get a nonce back.
#	calculate the sha256 of the nonce, a secret, the sha256 of the DER of your client cert and the observed sha256 of the server.
#	Do a get on /register?response=sha256-as-hex
#	Server calcualtes same (and knows the shared secret) and checks if it is correct
#	Server returns the sha256 of the secret and the sha256 (binary) from the response
#	Client checks that this matches

In this case - the secret is a RFID tag of someone authorized in the CRM system to pair payment terminals.
