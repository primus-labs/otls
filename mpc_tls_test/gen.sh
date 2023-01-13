# openssl genrsa -out ca.key
openssl ecparam -out ca.key -name secp256r1 -genkey
openssl req -new -x509 -key ca.key -out ca.crt -subj /C=CN/ST=SH/O=pado
# openssl req -new -key ca.key -out ca.csr
# openssl x509 -req -in ca.csr -signkey ca.key -out ca.crt


# openssl genrsa -out server.key
openssl ecparam -out server.key -name secp256r1 -genkey
openssl req -new -key server.key -out server.csr -subj /C=CN/ST=SZ/O=pado
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key  -CAcreateserial -out server.crt -extfile config.cfg -extensions myexts
