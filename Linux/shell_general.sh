# convert pfx to pem
openssl pkcs12 -in "path.pfx" -out "newfile.pem" -nodes
