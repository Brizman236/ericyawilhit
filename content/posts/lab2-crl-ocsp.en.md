---
title: "Lab 2 — CRL and OCSP: Implementing Revocation in a PKI with OpenSSL"
date: 2026-03-19
draft: false
tags:
  - PKI
  - OpenSSL
  - CRL
  - OCSP
  - Lab
description: "How to implement CRL and OCSP in a complete PKI with OpenSSL. Certificate revocation, OCSP Responder, and Apache Reverse Proxy."
cover:
  image: /images/lab2-cover.png
  alt: Lab 2 — CRL and OCSP
  relative: false
---

## Context & Objectives

In [Lab 1](https://github.com/Brizman236/Home-Labs/blob/main/PKI%20TLS%20Lab/Documentation.md),  I configured a complete PKI architecture consisting of a **Root CA**, an **Intermediate CA**, and a WEB server using **HTTPS**. The trust chain was successfully validated from a Windows client.

However, this infrastructure has a **critical gap**: **the absence of a certificate revocation mechanism**. In the current state of the Lab, if the WEB server's private key is compromised before its expiration date, the client will continue to trust the certificate as long as it has not yet expired. This could lead to a **Man-In-The-Middle** attack. The risk concerns not only the WEB server's private key, but also the private key of the **Intermediate CA**. Therefore, a **revocation** mechanism must be implemented to reduce the risk.

This second lab addresses this gap by introducing the two standard certificate revocation mechanisms:

- **CRL (Certificate Revocation List)** — a blacklist periodically published by a CA, listing revoked certificates
- **OCSP (Online Certificate Status Protocol)** — a real-time verification service that makes it possible to instantly determine the status of a certificate

Implementing these mechanisms also requires redesigning the existing PKI architecture. Indeed, Lab 1 used the `openssl x509` command to sign certificates — a manual approach that does not maintain a record of issued certificates. Revocation requires the use of `openssl ca`, which maintains an `index.txt` file serving as a certificate database and allowing certificates to be revoked.

The objectives of this lab are therefore to:

- Rebuild the PKI with `openssl ca` to have a complete registry
- Configure the **CDP (CRL Distribution Point)** in the certificates
- Deploy and test the **CRL**
- Deploy and test the **OCSP Responder**
- Validate revocation in real time from the Windows client

---

## Topologie

![Topologie Lab 2](/images/topologie-lab2-crl-ocsp.png)



---

## Network Configuration

| Machines Hostname IP Domain Name  |        |                |                                                     |
| ------------------------------------ | ------ | -------------- | --------------------------------------------------- |
| Root CA                              | RootCA | 192.168.122.20 | rootca1.cyber.lab                                   |
| Intermediate CA                      | SubCA  | 192.168.122.40 | subca1.cyber.lab                                    |
| Web Server                          | web    | 192.168.122.30 | [www.cyber.lab](http://www.cyber.lab) crl.cyber.lab |
| Windows Client                       | -      | DHCP           | -                                                   |

---

## PHASE 1: PKI Reconstruction

### Phase 1.1: Root CA Creation

```
# Folder structure
mkdir -p ~/pki/root/{private,certs,crl,csr,newcerts}

# Protect the private key directory
chmod 700 ~/pki/root/private

# Issued certificates registry 
touch ~/pki/root/index.txt

# Serial number — starts at 01 
echo 01 > ~/pki/root/serial 

# CRL number 
echo 01 > ~/pki/root/crlnumber

# Create the configuration file
nano pki/root/root.cnf

```

```
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = /root/pki/root
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
crlnumber         = $dir/crlnumber
private_key       = $dir/private/root.key
certificate       = $dir/certs/root.crt
crl               = $dir/crl/root.crl
default_md        = sha256
default_days      = 3650
default_crl_days  = 30
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
commonName              = supplied

[ req ]
default_bits        = 4096
prompt              = no
default_md          = sha256
distinguished_name  = dn

[ dn ]
C  = SN
ST = Senegal
O  = Cyber Lab
CN = Lab Root CA

[ v3_root_ca ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer

[ v3_intermediate_ca ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
crlDistributionPoints = URI:http://crl.cyber.lab/crl/root.crl
authorityInfoAccess = OCSP;URI:http://crl.cyber.lab/ocsp/root

[ ocsp ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
subjectKeyIdentifier = hash

```

The `.cnf` file of a **CA** is its issuance policy; it defines all the types of certificates it is authorized to issue. In our case, the `.cnf` file defines the extensions for the RootCA (`v3_root_ca`) and SubCA (`v3_intermediate_ca`) certificates.

- `crlDistributionPoints` specifies the endpoint from which the CRL can be retrieved, as does `authorityInfoAccess` for OCSP
- the `keyUsage` `cRLSign` specifies that this authority's private key can sign CRLs

With the configuration file in place, we can now generate the Root CA:

```
# Private key PEM pass : JG/IpvS3gxqzKg5J
openssl genrsa -aes256 -out ~/pki/root/private/root.key 4096
chmod 400 ~/pki/root/private/root.key

# Self-signed certificate
openssl req -config ~/pki/root/root.cnf \
  -key ~/pki/root/private/root.key \
  -new -x509 -days 7300 -sha256 \
  -extensions v3_root_ca \
  -out ~/pki/root/certs/root.crt

```

---

### Phase 1.2: Intermediate CA Creation

```
# Folder structure
mkdir -p ~/pki/intermediate/{private,certs,crl,csr,newcerts}
chmod 700 ~/pki/intermediate/private

touch ~/pki/intermediate/index.txt
echo 01 > ~/pki/intermediate/serial
echo 01 > ~/pki/intermediate/crlnumber

# Create the configuration file
nano ~/pki/intermediate/intermediate.cnf

```

```
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = /root/pki/intermediate
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
crlnumber         = $dir/crlnumber
private_key       = $dir/private/intermediate.key
certificate       = $dir/certs/intermediate.crt
crl               = $dir/crl/intermediate.crl
default_md        = sha256
default_days      = 365
default_crl_days  = 7
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
commonName              = supplied

[ req ]
default_bits        = 4096
prompt              = no
default_md          = sha256
distinguished_name  = dn

[ dn ]
C  = SN
ST = Senegal
L  = Dakar
O  = Cyber Lab
CN = Lab Intermediate CA

[ server_cert ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
crlDistributionPoints = URI:http://crl.cyber.lab/crl/intermediate.crl
authorityInfoAccess = OCSP;URI:http://crl.cyber.lab/ocsp/intermediate
subjectAltName = DNS:www.cyber.lab

[ ocsp ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
subjectKeyIdentifier = hash

```

We will now generate the private key and CSR for the Intermediate CA and then transfer it to the RootCA:

```
# Private key Pass PEM : +ptIxeoDsc+kVzer
openssl genrsa -aes256  -out ~/pki/intermediate/private/intermediate.key 4096 
chmod 400 ~/pki/intermediate/private/intermediate.key 

# Generate the CSR 
openssl req -config ~/pki/intermediate/intermediate.cnf -new -sha256 -key ~/pki/intermediate/private/intermediate.key -out ~/pki/intermediate/csr/intermediate.csr

# Copy the CSR to the RootCA
scp ~/pki/intermediate/csr/intermediate.csr  root@rootca1.cyber.lab:~/

```

Now, from the Root CA, we will create and sign the Intermediate CA certificate and send it back:

```
# Certificate creation 
openssl ca -config ~/pki/root/root.cnf \
  -extensions v3_intermediate_ca \
  -days 3650 -notext -md sha256 \
  -in ~/intermediate.csr \
  -out ~/intermediate.crt

# Send the certificate to the Intermediate CA
scp ~/intermediate.crt  root@subca1.cyber.lab:~/pki/intermediate/certs

```

---

### Phase 1.3: Reissuing the WEB Server Certificate

Previously, we generated the web server's private key in `/etc/ssl/lab/private` and the CSR in `/etc/ssl/lab/webserver.csr`. We will now transfer this CSR to the SubCA and issue the web server certificate:

```
scp /etc/ssl/lab/webserver.csr root@subca1.cyber.lab:~/

# On the SubCA
openssl ca -config ~/pki/intermediate/intermediate.cnf \
  -extensions server_cert \
  -days 365 -notext -md sha256 \
  -in ~/webserver.csr \
  -out ~/webserver.crt
  
# Create the trust chain
cat ~/pki/intermediate/certs/intermediate.crt webserver.crt > ca-chain

# Transfer the certificate and trust chain to the WEB Server
scp webserver.crt root@www.cyber.lab:/etc/ssl/lab/certs/
scp ca-chain.crt root@www.cyber.lab:/etc/ssl/lab/certs/

```

---

## PHASE 2: CRL & OCSP

During the previous configurations, we issued the certificates with their **CRL Distribution Points** (CDP) and the OCSP Responder endpoint. Each certificate is issued with a CDP containing the CRL of its issuer.
In this phase, we will configure the WEB server to host the CRLs and the OCSP Responder, generate the SubCA's CRL, configure the OCSP Responder, and perform a revocation test.

---

#### **Web Server Configuration**

The CRLs will be hosted under the `crl.cyber.lab` domain name, so we will register this name on the DNS server:



We will now create a VirtualHost that will host the CRL and OCSP site:

```
# On the WEB Server
mkdir -p /var/www/crl/crl
mkdir -p /var/www/crl/ocsp/root
mkdir -p /var/www/crl/ocsp/intermediate

# Create the VirtualHost
nano /etc/apache2/sites-available/crl.conf

```

```
<VirtualHost *:80>
    ServerName crl.cyber.lab
    DocumentRoot /var/www/crl

    <Directory /var/www/crl>
        Options Indexes
        AllowOverride None
        Require all granted
    </Directory>
    
</VirtualHost>

```

```
# Enable the Site
a2ensite crl.conf
systemctl reload apache2

```



#### Generating the CRL on the SubCA

```
openssl ca -config ~/pki/intermediate/intermediate.cnf \
  -gencrl \
  -out ~/pki/intermediate/crl/intermediate.crl
  
# Then read this CRL with 
openssl crl -in ~/pki/intermediate/crl/intermediate.crl -text

```

The CRL is generated and signed with the SubCA's key to prove its validity. No certificate has been revoked yet, as we can see below 👇



---

#### Configuring the OCSP Responder

The OCSP Responder is responsible for real-time verification of a certificate's status. It signs its responses to prevent a Man-In-The-Middle attack. 

When the client accesses the web site, it verifies the validity of the entire trust chain, starting with the Intermediate CA and then the WEB server certificate. 

We will configure two OCSP Responders: one hosted on the RootCA, responsible for responding to SubCA verification requests, and another hosted on the SubCA for the Server certificate.

> NB: In production, OCSP Responders are delegated to a dedicated server

**OCSP Responder on SubCA**

```
# Private key
openssl genrsa -out ~/pki/intermediate/private/ocsp.key 4096 
chmod 400 ~/pki/intermediate/private/ocsp.key

# CSR
openssl req -new \ -key ~/pki/intermediate/private/ocsp.key \ -out ~/pki/intermediate/csr/ocsp.csr \ -subj "/C=SN/ST=Senegal/O=Cyber Lab/CN=OCSP Responder"

# Certificate issuance
openssl ca -config ~/pki/intermediate/intermediate.cnf \
  -extensions ocsp \
  -days 365 -notext -md sha256 \
  -in ~/pki/intermediate/csr/ocsp.csr \
  -out ~/pki/intermediate/certs/ocsp.crt

```

**OCSP Responder on Root CA**

```
# Private key
openssl genrsa -out ~/pki/root/private/ocsp.key 4096 
chmod 400 ~/pki/root/private/ocsp.key

# CSR
openssl req -new  -key ~/pki/root/private/ocsp.key -out ~/pki/root/csr/ocsp.csr  -subj "/C=SN/ST=Senegal/O=Cyber Lab/CN=OCSP Responder RootCA"

# Certificate issuance
openssl ca -config ~/pki/root/root.cnf \
  -extensions ocsp \
  -days 365 -notext -md sha256 \
  -in ~/pki/root/csr/ocsp.csr \
  -out ~/pki/root/certs/ocsp.crt

```

The OCSP Responder is a service that will run continuously through a listening port. However, we specified the endpoint on the WEB server. The question is: how can the client's request, which will be sent to the web server, reach the SubCA?

For this, we will use a **Reverse Proxy** that will redirect the request to the SubCA and Root CA while keeping them isolated.

Let's first start the OCSP Responders:

```
# On the RootCA
openssl ocsp \
  -port 2560 \
  -text \
  -index ~/pki/root/index.txt \
  -CA ~/pki/root/certs/root.crt \
  -rkey ~/pki/root/private/ocsp.key \
  -rsigner ~/pki/root/certs/ocsp.crt \
  -out ~/ocsp.log &

# On the SubCA
openssl ocsp \
  -port 2560 \
  -text \
  -index ~/pki/intermediate/index.txt \
  -CA ~/pki/intermediate/certs/intermediate.crt \
  -rkey ~/pki/intermediate/private/ocsp.key \
  -rsigner ~/pki/intermediate/certs/ocsp.crt \
  -out ~/ocsp.log &

```

Next, let's configure the Reverse Proxy on the Web Server:

```
# Enable the required modules
a2enmod proxy proxy_http
systemctl restart apache2

# Modify crl.cnf
nano /etc/apache2/sites-available/crl.conf

```

```
<VirtualHost *:80>
    ServerName crl.cyber.lab
    DocumentRoot /var/www/crl

    <Directory /var/www/crl>
        Options Indexes
        AllowOverride None
        Require all granted
    </Directory>

    # Reverse Proxy OCSP Root
    ProxyPass /ocsp/root http://rootca1.cyber.lab:2560
    ProxyPassReverse /ocsp/root http://rootca1.cyber.lab:2560
    # OCSP Intermediate
    ProxyPass /ocsp/intermediate http://subca1.cyber.lab:2560
    ProxyPassReverse /ocsp/intermediate http://subca1.cyber.lab:2560
</VirtualHost>


```

When a request is sent to `/ocsp/intermediate`, it will be redirected to `http://subca1.cyber.lab:2560`. Then, when the SubCA responds, the Proxy will replace the URL contained in the Header with its own, `crl.cyber.lab`. The same principle applies to a request sent to the `/ocsp/root` endpoint. Let's restart the `apache2` service.

---

Let's test the OCSP Responder from the RootCA:

```
openssl ocsp   -issuer ~/intermediate.crt   -cert ~/webserver.crt   -url http://crl.cyber.lab/ocsp/intermediate -CAfile ~/pki/root/certs/root.crt

openssl ocsp   -issuer ~/pki/root/certs/root.crt   -cert ~/intermediate.crt   -url http://crl.cyber.lab/ocsp/root   -CAfile ~/pki/root/certs/root.crt

```



---

#### **Revocation Test**

We will now revoke the WEB server certificate from the SubCA and regenerate the CRL:

```
openssl ca -config ~/pki/intermediate/intermediate.cnf -revoke ~/pki/intermediate/newcerts/01.pem

# Generate the CRL
openssl ca -config ~/pki/intermediate/intermediate.cnf \
  -gencrl \
  -out ~/pki/intermediate/crl/intermediate.crl

# Copy the CRL to the WEB Server
scp ~/pki/intermediate/crl/intermediate.crl root@www.cyber.lab:/var/www/crl/crl

```

By running the OCSP request again from the RootCA, we get a response stating that the certificate has been revoked:



On the client's browser, the revocation is not detected. Why?
To understand the reason, let's first define the difference between a **public PKI** and a **private PKI**.

---

#### Public PKI & Private PKI

A **public PKI** has a **globally known** CA such as **DigiCert** or **Let's Encrypt**, which is included in Trust Stores (Google, Mozilla, etc.). The Root CA is pre-installed in the operating system and in the browser. 

A **private PKI**, on the other hand, is one with a **CA** generated by an organization for its own activities. The Root CA is not included in Trust Stores.

In browsers, primarily in **Google Chrome**, there is a database of CRLs collected by Google and distributed with each Google Chrome update. This database is called a **CRLSet**. Revocation is therefore checked locally by the browser without making network requests. 

> This is why the browser on our client did not detect the revocation.