keys and certs in this folder were created as follows:

$ openssl ecparam -name secp521r1 -genkey -noout -out ec-key1.pem
$ openssl req -new -x509 -key ec-key1.pem -out ec-pubCert1.pem -days 1500
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) []:CA
State or Province Name (full name) []:ON
Locality Name (eg, city) []:Toronto
Organization Name (eg, company) []:SecureKey inc.
Organizational Unit Name (eg, section) []:trustbloc
Common Name (eg, fully qualified host name) []:localhost
Email Address []:

$ openssl ecparam -name secp521r1 -genkey -noout -out ec-key2.pem
$ openssl req -new -x509 -key ec-key2.pem -out ec-pubCert2.pem -days 1500
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) []:CA
State or Province Name (full name) []:Ontario
Locality Name (eg, city) []:Toronto
Organization Name (eg, company) []:Securekey
Organizational Unit Name (eg, section) []:Trustbloc
Common Name (eg, fully qualified host name) []:localhost
Email Address []:


$ openssl ecparam -name secp521r1 -genkey -noout -out ec-key3.pem
$ openssl req -new -x509 -key ec-key3.pem -out ec-pubCert3.pem -days 1500
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) []:CA
State or Province Name (full name) []:Ontario
Locality Name (eg, city) []:Toronto
Organization Name (eg, company) []:Securekey
Organizational Unit Name (eg, section) []:Trustbloc
Common Name (eg, fully qualified host name) []:localhost
Email Address []:
