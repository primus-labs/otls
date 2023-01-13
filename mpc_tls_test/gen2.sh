openssl genrsa -out myrootcert.key
# openssl req -new -x509 -key ca.key -out ca.crt
openssl req -new -key myrootcert.key -out myrootcert.csr
openssl x509 -req -in myrootcert.csr -signkey myrootcert.key -out myrootcert.crt

# openssl genrsa -out client_ca.key
# # openssl req -new -x509 -key ca.key -out ca.crt
# openssl req -new -key client_ca.key -out client_ca.csr
# openssl x509 -req -in client_ca.csr -signkey client_ca.key -out client_ca.crt


# openssl genrsa -out client.key
# openssl req -new -key client.key -out client.csr
# openssl x509 -req -in client.csr -CA client_ca.crt -CAkey client_ca.key  -CAcreateserial -out client.crt

openssl genrsa -out ca.key
openssl req -new -key ca.key -out ca.csr
openssl x509 -req -in ca.csr -CA myrootcert.crt -CAkey myrootcert.key  -CAcreateserial -out ca.crt

openssl genrsa -out server.key
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key  -CAcreateserial -out server.crt
