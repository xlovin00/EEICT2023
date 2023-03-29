# EEICT 2023
# Bc. Norbert Lovinger
# xlovin00@vutbr.cz

# Pseudonym certificates are a privacy-enhancing tool that can be used to protect 
# the privacy of users when interacting with an application or service. 
# These certificates allow users to authenticate themselves without revealing their true identity,
# thus reducing the risk of identity theft or other privacy breaches.

# 1. 
# Generate a public-private key pair for the user: 
# The first step is to generate a public-private key pair for each user who wants to use the application. 
# This can be done using standard cryptographic tools such as OpenSSL.

import time
import os
import hashlib
import base64
from OpenSSL import crypto


# Generate a new private key for user
user_pri_key = crypto.PKey()
user_pri_key.generate_key(crypto.TYPE_RSA, 3072)

# Generate a public key from the private key for user
user_pub_key = crypto.dump_publickey(crypto.FILETYPE_PEM, user_pri_key)

# Save the private key to a file
with open('user_private_key.pem', 'wb') as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, user_pri_key))

# Save the public key to a file
with open('user_public_key.pem', 'wb') as f:
    f.write(user_pub_key)

# Reading public key and private key
with open('user_public_key.pem', 'rb') as f:
    key_data = f.read()
key = crypto.load_publickey(crypto.FILETYPE_PEM, key_data)
print("users real public key\n"+crypto.dump_publickey(crypto.FILETYPE_PEM, key).decode('utf-8'))


with open('user_private_key.pem', 'rb') as f:
    key_data = f.read()
key2 = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)
print("users real private key\n"+crypto.dump_privatekey(crypto.FILETYPE_PEM, key2).decode('utf-8'))

#------------------------------------------------

# 2.
# Create a certificate for each user: 
# Once the key pair has been generated, you can create a certificate that associates the user's public key 
# with a pseudonym or alias. This certificate can be signed by a trusted third party, 
# such as a certificate authority (CA), to provide additional assurance of the user's identity.

# Define a unique identifier for the user (e.g., user ID, email address, etc.)
user_id = "carsharinguser1"

# Generate a hash of the user ID
hash = hashlib.sha256(user_id.encode()).digest()

# Encode the hash as a Base64 string
hash_base64 = base64.b64encode(hash).decode()

# Create the pseudonym identity string by combining the user ID and the hash
pseudonym_identity = f"{user_id}::{hash_base64}"

# Load the user's public key from a file
with open('user_public_key.pem', 'rb') as f:
    public_key_data = f.read()
user_pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, public_key_data)

# Generate a certificate signing request (CSR) for User 
csr_user = crypto.X509Req()
csr_user.get_subject().CN = pseudonym_identity  # Set the CN field to the user's pseudonym
csr_user.set_pubkey(user_pub_key)
csr_user.sign(user_pri_key, 'sha256')  # Sign the CSR with the user's private key

# Create a new self-signed certificate = in real-world use CA's certificates
key_ca = crypto.PKey()
key_ca.generate_key(crypto.TYPE_RSA, 3072)
cert_ca = crypto.X509()
cert_ca.get_subject().CN = 'Trusted Third Party'
cert_ca.set_serial_number(1)
cert_ca.gmtime_adj_notBefore(0)
cert_ca.gmtime_adj_notAfter(315360000) # valid for 10 years
cert_ca.set_issuer(cert_ca.get_subject())
cert_ca.set_pubkey(key_ca)
cert_ca.sign(key_ca, 'sha256')

# Write the CA's private key to a file
with open('ca_key.pem', 'wb') as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key_ca))

# Write the CA's certificate to a file
with open('ca_cert.pem', 'wb') as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert_ca))

# Load the CA's certificate and private key from files
with open('ca_cert.pem', 'rb') as f:
    ca_cert_data = f.read()
ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_data)
print(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode('utf-8'))

with open('ca_key.pem', 'rb') as f:
    ca_key_data = f.read()
ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key_data)
print(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key).decode('utf-8'))

# Generate a new user certificate signed by the CA
cert_user = crypto.X509()
cert_user.set_subject(csr_user.get_subject())
cert_user.set_pubkey(csr_user.get_pubkey())
cert_user.gmtime_adj_notBefore(0)
cert_user.gmtime_adj_notAfter(315360000)  # Set the certificate's validity period (in seconds)
cert_user.set_issuer(ca_cert.get_subject())
cert_user.set_serial_number(int.from_bytes(os.urandom(20), 'big'))  # Generate a random serial number
cert_user.sign(ca_key, 'sha256')

# Save the certificate to a file
with open('cert_pseudo_user.pem', 'wb') as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert_user))

#------------------------------------------------

# 3.
# Use the certificate to authenticate the user: 
# When the user wants to authenticate themselves to the application, 
# they can present their pseudonym certificate instead of their real identity. 
# The application can then verify the certificate's authenticity by checking the signature 
# against the trusted third party's public key.

# Load the trusted third party's public key
with open('ca_cert.pem', 'rb') as f:
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

# Load the user's pseudonym certificate
with open('cert_pseudo_user.pem', 'rb') as f:
    cert_pseudo_user = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

# Verify the user's certificate using the trusted public key
store = crypto.X509Store()
store.add_cert(ca_cert)
store.add_cert(cert_pseudo_user)
store_ctx = crypto.X509StoreContext(store, cert_pseudo_user)
store_ctx.verify_certificate()

# If the certificate is valid, extract the user's pseudonym
pseudonym = cert_pseudo_user.get_subject().CN
print("Car sharing application access granted for user\n"+pseudonym)

# Use the pseudonym in place of the user's real identity: 
# Once the user has been authenticated, the application can use the pseudonym in place of 
# the user's real identity for any subsequent interactions. 
# This can help protect the user's privacy by reducing the amount of 
# personal information that is shared with the application.

# Overall, using pseudonym certificates can be a powerful tool 
# for protecting user privacy in your application. 
# By allowing users to authenticate themselves without revealing their true identity, 
# you can help build trust and confidence in your application while also protecting user privacy.