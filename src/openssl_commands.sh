# Generate a CA key - key is encrypted using des3
openssl genrsa -des3 -out rootCA.key 4096

# Generate a CA cert
openssl req -x509 -new -key rootCA.key -sha256 -days 1024 -out rootCA.crt

# Generate a server key
openssl genrsa -out server.key 2048

# Generate server csr
openssl req -new -sha256 -key server.key -out server.csr

# Sign server.csr with CA cert
openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out server.crt

# Show contents of certificate
openssl x509 -in rootCA.crt -noout -text
