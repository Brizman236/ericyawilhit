---
title: "Implementing a PKI with SoftHSM2 and PAdES: Securing the Issuance of University Diplomas with PyHanko"
date: 2026-04-17
draft: false
description: "Faced with the widespread issue of diploma forgery, this technical guide details the implementation of a sovereign trust infrastructure. Through a practical laboratory using SoftHSM2, OpenSSL, and PyHanko, discover how PAdES-LTV digital signatures can guarantee the authenticity and integrity of university degrees, instantly verifiable by recruiters through Adobe Acrobat."
cover:
  image: /images/lab3-cover.jpg
  alt: Digital signature of university diplomas
  relative: false
---

## Context & Objectives

In the university sector and on the African job market, widespread diploma forgery is a major concern. This is largely due to the lack of reliable infrastructure capable of verifying the validity of diplomas issued by African universities and schools.

With PKI, such a verification infrastructure can be implemented using **digital signatures**.

How can a digital signature prevent diploma forgery? How can we determine whether a digitally signed diploma is valid?

Diploma forgery occurs when a *graduate* applies for a job or an academic program. In this scenario, we have two main actors involved: the university that issued the diploma and the recruiter who receives it.

How can the recruiter trust the diploma presented by the student? How can they verify its validity?

To achieve this, the recruiter needs a trusted third party recognized as a trust authority. This entity (the MESRI — Ministry of Higher Education, Research and Innovation in Senegal) will not sign the diplomas directly. Its role will be to certify the identity of the university, which guarantees:

- that the signature placed on the diploma actually comes from the university in question and not from a malicious third party;
- the integrity of the document, since the signature would become invalid if the document were modified;
- non-repudiation: the university cannot deny having signed/issued the diploma.

The recruiter will not need to contact the university for verification. The university's certificate is embedded in the PDF, allowing Adobe Acrobat to extract it and automatically perform the verification, then build the chain of trust back to the MESRI.

We know that certificates all have an expiration date. Therefore, it would not be possible to verify the validity of a diploma if the signer's certificate has expired, or if the private key used to sign the document has been compromised.

How can the validity of a diploma be preserved in these two situations? At what point in time should the signature be considered valid?

The digital signature does not need to be valid at the time of verification, but rather at the time of issuance. This is what **PAdES-LTV** solves, which we will explore later.

To implement this trust infrastructure, we will adopt the following hierarchy:

- a Root CA representing the MESRI;
- a SubCA representing the University (in our case, UCAD);
- the person authorized to sign diplomas within the university; in our case, the Rector.

In this lab, we will implement:

- a PKI with **SoftHSM2**;
- a **signing certificate** for the Rector;
- PDF signing with PyHanko (PAdES);
- verification with Adobe Acrobat Reader.

**Learning Objectives**

- Understand PKCS#11 with SoftHSM2;
- Implement PAdES;
- Explore a concrete use case — digital sovereignty.

---

## Topology

![/images/lab3-topologie.jpg](/images/lab3-topologie.jpg)

---

## Network Configuration

| Machine | Role | OS | HSM | IP | FQDN |
|---|---|---|---|---|---|
| `mesri-ca` | Root CA | Ubuntu Server | SoftHSM2 | 192.168.122.20 | rootca1.cyber.lab |
| `ucad-ca` | Intermediate CA | Ubuntu Server | SoftHSM2 | 192.168.122.40 | subca1.cyber.lab |
| `recteur` | PDF Signer | Fedora | SoftHSM2 | DHCP | — |
| `dns` | DNS | Ubuntu Server | — | 192.168.122.10 | dns.cyber.lab |
| `client` | Adobe Reader | Windows 10 | — | DHCP | — |
| `crl-server` | Revocation | Ubuntu Server | SoftHSM2 | 192.168.122.30 | crl.cyber.lab |

---

## PHASE 1: Tool Installation

In this lab, we need:

- **OpenSSL CA**
- **SoftHSM2**: it simulates a secure hardware module by storing private keys in an encrypted database on disk. It stores private keys outside the standard filesystem.
- **GnuTLS**: a cryptographic tool suite, notably providing `p11tool` for interacting with PKCS#11 tokens. It is used to list, inspect, and verify private keys stored in SoftHSM2.
- **libengine-pkcs11-openssl**: a PKCS#11 plugin for OpenSSL. It allows OpenSSL to delegate cryptographic operations to a PKCS#11 token such as SoftHSM2.
- **PyHanko**: a Python library specialized in PDF signing. It supports PAdES, LTV, and timestamps.
- **OpenSC**: a suite of tools for smart cards and PKCS#11 tokens. It provides `pkcs11-tool` for interacting with SoftHSM2. It will be used to generate key pairs inside SoftHSM.
- **python-pkcs11**: a Python library allowing applications to use PKCS#11.

To install them, run the following commands:

On the Root CA and SubCA:

```bash
apt update && apt install -y openssl softhsm2 gnutls-bin libengine-pkcs11-openssl opensc
````

On the Revocation Server:

```bash
apt update && apt install -y apache2
```

On Fedora:

```bash
sudo dnf update -y
sudo dnf install -y softhsm opensc gnutls-utils python3-pip libengine-pkcs11-openssl
pip install 'pyHanko[pkcs11,image-support,opentype,qr]'
pip install pyhanko-cli python-pkcs11
```

---

## PHASE 2: MESRI PKI (Root CA)

### Phase 2.1 — Initialize SoftHSM2 on the Root CA

We are going to initialize a **token** in the Root CA's SoftHSM2.

A token is a logical instance of the HSM that can contain cryptographic objects (private keys, public keys, certificates, secret data). In our case, it will contain the Root CA's private key.

It has:

- A label/name;
    
- A user PIN: used to manipulate the objects stored inside it;
    
- An SO PIN: used by the administrator.
    

Let's initialize our token:

```bash
softhsm2-util --init-token --slot 0 --label "mesri-root" --pin 1234 --so-pin 2468
```

![/images/Pasted image 20260321010741.png](/images/Pasted%20image%2020260321010741.png)

The slot (the physical or logical location where a token is inserted) has been reset to:

```text
1893920401
```

---

### Phase 2.2 — Generate the Root CA Private Key in SoftHSM2

We will use the `pkcs11-tool` utility while specifying the **PKCS#11** library of SoftHSM:

```text
/usr/lib/softhsm/libsofthsm2.so
```

`pkcs11-tool` is a generic tool and does not know which HSM is being used, which is why we must explicitly specify it.

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen \
  --key-type rsa:4096 \
  --label "mesri-root-key" \
  --token-label "mesri-root"
```

![/images/Pasted image 20260321012220.png](/images/Pasted%20image%2020260321012220.png)

Let's verify the contents of the token to make sure the key pair is present:

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --list-objects \
  --token-label "mesri-root"
```

![/images/Pasted image 20260321012600.png](/images/Pasted%20image%2020260321012600.png)

---

### Phase 2.3 — Creating the Root CA Certificate

First, we will create the Root CA directory structure:

```bash
mkdir -p /root/pki/root/{certs,crl,csr,newcerts}
touch /root/pki/root/index.txt
echo 01 > /root/pki/root/serial
echo 01 > /root/pki/root/crlnumber
```

Then create the `/root/pki/root/root.cnf` configuration file:

```toml
[ ca ]
default_ca = CA_default
# Main entry point — tells OpenSSL which section
# to use as the default configuration
openssl_conf = openssl_init

[ openssl_init ]
engines = engine_section

[ engine_section ]
pkcs11 = pkcs11_section

[ pkcs11_section ]
engine_id = pkcs11
MODULE_PATH = /usr/lib64/pkcs11/opensc-pkcs11.so
init = 0

[ CA_default ]
# Working directories
dir               = /root/pki/root
# Root CA PKI root directory

certs             = $dir/certs
# Stores issued certificates

crl_dir           = $dir/crl
# Stores generated CRLs

new_certs_dir     = $dir/newcerts
# Stores a copy of every signed certificate
# named after its serial number

database          = $dir/index.txt
# Registry of all issued certificates
# Format: Status | Expiry | Serial | DN

serial            = $dir/serial
# File containing the next serial number
# Automatically incremented after each signature

crlnumber         = $dir/crlnumber
# Number of the next generated CRL

private_key       = $dir/private/root.key
# We will not put anything here — the key is stored in SoftHSM2
# A PKCS#11 URI will be used instead

certificate       = $dir/certs/root.crt
# Self-signed Root CA certificate

crl               = $dir/crl/root.crl
# Current Root CA CRL

default_md        = sha256
# Hashing algorithm — SHA256 is the current standard

default_days      = 3650
# Validity period of issued certificates — 10 years

default_crl_days  = 30
# CRL validity period — 30 days

policy            = policy_strict
# CSR validation policy

[ policy_strict ]
# Required fields and their constraints
# match    = must exactly match the Root CA
# supplied = must be provided in the CSR
# optional = may be absent
countryName             = supplied
stateOrProvinceName     = supplied
organizationName        = supplied
commonName              = supplied

[ req ]
default_bits        = 4096
# Default key size — 4096 bits for Root CA

prompt              = no
# Do not interactively request DN fields

default_md          = sha256
distinguished_name  = dn

[ dn ]
# Root CA Distinguished Name
C  = SN
# Senegal

ST = Senegal
O  = MESRI
# Ministry of Higher Education

CN = MESRI Root CA
# Name that will appear in certificates

[ v3_ca ]
# Extensions applied to the Root CA certificate
basicConstraints = critical, CA:true
# This entity IS a CA
# critical = the client must understand this extension

keyUsage = critical, keyCertSign, cRLSign
# keyCertSign = can sign certificates
# cRLSign     = can sign CRLs

subjectKeyIdentifier = hash
# Public key fingerprint
# Used to identify the key in the chain

authorityKeyIdentifier = keyid:always, issuer
# Reference to the key that signed this certificate
# For the Root CA = references itself

[ v3_intermediate_ca ]
# Extensions applied to the Intermediate CA certificate
basicConstraints = critical, CA:true, pathlen:0
# CA:true   = this is a CA
# pathlen:0 = cannot create another SubCA below it

keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
crlDistributionPoints = URI:http://crl.cyber.lab/crl/root.crl
authorityInfoAccess = OCSP;URI:http://crl.cyber.lab/ocsp/root
# The client looks for the Root CA CRL here

[ ocsp ]
# Extensions for the Root CA OCSP Responder certificate
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
# Explicitly authorizes this certificate to sign
# OCSP responses

subjectKeyIdentifier = hash
noCheck = ignored
# RFC 6960 — tells the client not to check
# the revocation status of THIS OCSP certificate
# prevents an infinite validation loop
```

To generate the Root CA certificate, we first need to retrieve the PKCS#11 URI of the key by listing the objects in the `mesri-root` token using GnuTLS's `p11tool`:

```bash
p11tool --list-all --login "pkcs11:token=mesri-root" --provider /usr/lib/softhsm/libsofthsm2.so
```

Example output:

```text
pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=cdb4e58ef0e2ee91;token=mesri-root;object=mesri-root-key;type=private
```

Then use it to create the certificate:

```bash
openssl req -new -x509 \
  -engine pkcs11 \
  -keyform engine \
  -key "pkcs11:token=mesri-root;object=mesri-root-key;type=private;pin-value=1234" \
  -config /root/pki/root/root.cnf \
  -extensions v3_ca \
  -days 7300 \
  -sha256 \
  -out /root/pki/root/certs/root.crt
```

---

### Phase 2.4 — Generate the Initial Root CA CRL

```bash
openssl ca -config /root/pki/root/root.cnf \
  -gencrl \
  -keyfile "pkcs11:token=mesri-root;object=mesri-root-key;type=private;pin-value=1234" \
  -keyform engine \
  -engine pkcs11 \
  -out /root/pki/root/crl/root.crl
```

We have finished creating the Root CA. Let's now move on to the SubCA, representing the university — UCAD in our case.

---

## PHASE 3 — UCAD SubCA

The SubCA configuration will be almost identical to the Root CA configuration. The main difference is that the SubCA certificate must be signed by the Root CA.

First, let's create the directory structure and configuration file:

```bash
mkdir -p /root/pki/intermediate/{certs,crl,csr,newcerts}
touch /root/pki/intermediate/index.txt
echo 01 > /root/pki/intermediate/serial
echo 01 > /root/pki/intermediate/crlnumber

nano /root/pki/intermediate/intermediate.conf
```

```ini
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
certificate       = $dir/certs/intermediate.crt
crl               = $dir/crl/intermediate.crl
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
O  = UCAD
CN = UCAD Intermediate CA

[ recteur ]
keyUsage = digitalSignature, nonRepudiation
extKeyUsage = emailProtection
basicConstraints = CA:FALSE
crlDistributionPoints = URI:http://crl.cyber.lab/crl/intermediate.crl
authorityInfoAccess = OCSP;URI:http://crl.cyber.lab/ocsp/intermediate

[ ocsp ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
subjectKeyIdentifier = hash
noCheck = ignored
```

---

### Phase 3.1 — Initialize SoftHSM2 on the SubCA

We will create a token named `ucad-intermediate`:

```bash
softhsm2-util --init-token --slot 0 --label "ucad-subca" --pin 1234 --so-pin 5678
```

**Generate the SubCA private key in SoftHSM2**

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen \
  --key-type rsa:4096 \
  --label "ucad-subca-key" \
  --token-label "ucad-subca"
```

### Phase 3.2 — Generate the SubCA CSR and Issue Its Certificate

```bash
openssl req -new \
  -engine pkcs11 \
  -keyform engine \
  -key "pkcs11:token=ucad-subca;object=ucad-subca-key;type=private;pin-value=1234" \
  -config /root/pki/intermediate/intermediate.cnf \
  -out /root/pki/intermediate/csr/intermediate.csr
```

#### Issue the SubCA Certificate

After copying the CSR to the Root CA, we will use `openssl ca` to issue the SubCA certificate:

```bash
openssl ca -config /root/pki/root/root.cnf \
  -extensions v3_intermediate_ca \
  -days 3650 -notext -md sha256 \
  -engine pkcs11 \
  -keyform engine \
  -keyfile "pkcs11:token=mesri-root;object=mesri-root-key;type=private;pin-value=1234" \
  -in ~/ucad-subca.csr \
  -out ~/intermediate.crt

# Copy the MESRI and UCAD certificates to the SubCA
scp intermediate.crt root@subca1.cyber.lab:~/
```

---

## PHASE 4 — The Revocation Server

It will be used in our lab to expose revocation endpoints (CRLs and OCSP Responders) through HTTP using Apache.

In production, a dedicated server is typically used to host OCSP Responders, keeping the Root CA isolated.

In our lab, we will start the OCSP Responders on the Root CA and SubCA and use a reverse proxy on the revocation server to keep them isolated.

The CRLs will be generated and deployed to the server using `scp`.

### PHASE 4.1 — Issue the OCSP Responder Certificates

We have two OCSP Responders, one on the Root CA and another on the SubCA.

First, we will generate their private keys in the SoftHSM2 instances:

```bash
# On the Root CA
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen \
  --key-type rsa:4096 \
  --label "mesri-ocsp-key" \
  --token-label "mesri-root"

# On the SubCA
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen \
  --key-type rsa:4096 \
  --label "ucad-ocsp-key" \
  --token-label "ucad-subca"
```

Then generate the CSRs and issue the certificates:

```bash
# On the Root CA
openssl req -new \
  -engine pkcs11 \
  -keyform engine \
  -key "pkcs11:token=mesri-root;object=mesri-ocsp-key;type=private;pin-value=1234" \
  -subj "/C=SN/ST=Senegal/O=MESRI/CN=MESRI OCSP Responder" \
  -out /root/pki/root/csr/ocsp-root.csr

openssl ca -config /root/pki/root/root.cnf \
  -extensions ocsp \
  -days 365 -notext -md sha256 \
  -engine pkcs11 \
  -keyform engine \
  -keyfile "pkcs11:token=mesri-root;object=mesri-root-key;type=private;pin-value=1234" \
  -in /root/pki/root/csr/ocsp-root.csr \
  -out /root/pki/root/certs/ocsp-root.crt

# On the SubCA
openssl req -new \
  -engine pkcs11 \
  -keyform engine \
  -key "pkcs11:token=ucad-subca;object=ucad-ocsp-key;type=private;pin-value=1234" \
  -subj "/C=SN/ST=Senegal/O=UCAD/CN=UCAD OCSP Responder" \
  -out /root/pki/intermediate/csr/ocsp-ucad.csr

openssl ca -config /root/pki/intermediate/intermediate.cnf \
  -extensions ocsp \
  -days 365 -notext -md sha256 \
  -engine pkcs11 \
  -keyform engine \
  -keyfile "pkcs11:token=ucad-subca;object=ucad-subca-key;type=private;pin-value=1234" \
  -in /root/pki/intermediate/csr/ocsp-ucad.csr \
  -out /root/pki/intermediate/certs/ocsp-ucad.crt
```

---

### PHASE 4.2 — Apache Configuration

We will create and configure a VirtualHost that will expose our endpoints.

**Create the directories on the server:**

```bash
mkdir -p /var/www/revoke/crl
mkdir -p /var/www/revoke/ocsp/{root,intermediate}
```

**VirtualHost configuration file: `/etc/apache2/sites-available/revoke.conf`**

```apache
<VirtualHost *:80>
    ServerName crl.cyber.lab
    DocumentRoot /var/www/revoke

    <Directory /var/www/revoke>
        Options Indexes
        AllowOverride None
        Require all granted
    </Directory>

    # Reverse Proxy for Root OCSP
    ProxyPass /ocsp/root http://rootca1.cyber.lab:2560
    ProxyPassReverse /ocsp/root http://rootca1.cyber.lab:2560

    # Intermediate OCSP
    ProxyPass /ocsp/intermediate http://subca1.cyber.lab:2560
    ProxyPassReverse /ocsp/intermediate http://subca1.cyber.lab:2560
</VirtualHost>
```

**Enable the required modules and the site:**

```bash
a2enmod proxy proxy_http
a2ensite revoke.conf
systemctl reload apache2
```

To use PKCS#11 when starting an OCSP Responder, we first need to create the PKCS#11 provider in the OpenSSL configuration file `/etc/ssl/openssl.cnf`.

First, install the `pkcs11-provider` package:

```bash
apt install -y pkcs11-provider
```

Then modify `openssl.cnf`:

```ini
...

[provider_sect]
default = default_sect
pkcs11  = pkcs11_sect

...

[ pkcs11_sect ]
module = /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so
pkcs11-module-path = /usr/lib/softhsm/libsofthsm2.so
activate = 1

[default_sect]
activate = 1

...
```

**Start the OCSP Responders:**

```bash
# On the Root CA
openssl ocsp \
  -port 2560 \
  -text \
  -index ~/pki/root/index.txt \
  -CA ~/pki/root/certs/root.crt \
  -rkey "pkcs11:token=mesri-root;object=mesri-ocsp-key;type=private;pin-value=1234" \
  -rsigner ~/pki/root/certs/ocsp-root.crt \
  -out ~/ocsp.log &

# On the SubCA
openssl ocsp \
  -port 2560 \
  -text \
  -index ~/pki/intermediate/index.txt \
  -CA ~/pki/intermediate/certs/intermediate.crt \
  -rkey "pkcs11:token=ucad-subca;object=ucad-ocsp-key;type=private;pin-value=1234" \
  -rsigner ~/pki/intermediate/certs/ocsp-ucad.crt \
  -out ~/ocsp.log &
```

To avoid the `No CKA_ID in source object` error, we must assign the same IDs to the keys of each OCSP Responder:

```bash
# On the Root CA
p11tool --login "pkcs11:token=mesri-root;object=mesri-ocsp-key;type=private;pin-value=1234" --set-id=01
p11tool --login "pkcs11:token=mesri-root;object=mesri-ocsp-key;type=public;pin-value=1234" --set-id=01

# On the SubCA
p11tool --login "pkcs11:token=ucad-subca;object=ucad-ocsp-key;type=private;pin-value=1234" --set-id=02
p11tool --login "pkcs11:token=ucad-subca;object=ucad-ocsp-key;type=public;pin-value=1234" --set-id=02
```

**Generate and publish the CRLs:**

```bash
# On the Root CA
openssl ca -config /root/pki/root/root.cnf \
  -gencrl \
  -keyfile "pkcs11:token=mesri-root;object=mesri-root-key;type=private;pin-value=1234" \
  -keyform engine \
  -engine pkcs11 \
  -out /root/pki/root/crl/root.crl

scp /root/pki/root/crl/root.crl root@192.168.122.30:/var/www/revoke/crl/

# On the SubCA
openssl ca -config /root/pki/intermediate/intermediate.cnf \
  -gencrl \
  -keyfile "pkcs11:token=ucad-subca;object=ucad-subca-key;type=private;pin-value=1234" \
  -keyform engine \
  -engine pkcs11 \
  -out /root/pki/intermediate/crl/intermediate.crl

scp /root/pki/intermediate/crl/intermediate.crl root@192.168.122.30:/var/www/revoke/crl/
```

---

## PHASE 5 — Rector Certificate

The Rector needs a digital identity in order to sign diplomas.

It consists of two essential elements:

- The private key: stored in SoftHSM and never leaves it;
    
- The Rector's certificate, issued by the UCAD SubCA with the extension required for signing.
    

To create this digital identity, we will:

- Generate the Rector's private key and CSR in SoftHSM;
    
- Create a certificate template on the SubCA and issue the Rector's certificate;
    
- Configure PyHanko to use the private key and certificate to sign PDFs.
    

### PHASE 5.1 — Generate the Private Key in the Rector's SoftHSM

By default, SoftHSM can only be used in root mode. We will create a user configuration to allow the Rector to use their private key.

```bash
mkdir -p ~/.config/softhsm2
mkdir -p ~/.softhsm2/tokens

cat > ~/.config/softhsm2/softhsm2.conf << EOF
directories.tokendir = $HOME/.softhsm2/tokens/
objectstore.backend = file
EOF

export SOFTHSM2_CONF=~/.config/softhsm2/softhsm2.conf
```

The user's tokens will be stored in:

```text
~/.softhsm2/tokens
```

Initialize the token:

```bash
softhsm2-util --init-token --slot 0 --label "recteur" --pin 1234 --so-pin 5678
```

Generate the keys:

```bash
pkcs11-tool --module /usr/lib64/softhsm/libsofthsm.so \
  --login \
  --token-label "recteur" \
  --pin 1234 \
  --keypairgen \
  --key-type rsa:2048 \
  --label "recteur-key"
```

Generate the CSR:

```bash
openssl req -new \
  -engine pkcs11 \
  -keyform engine \
  -key "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=247e8903bf1b2f9e;token=recteur;object=recteur-key;type=public?pin-value=1234" \
  -out ~/recteur-diallo.csr \
  -subj "/C=SN/ST=Senegal/O=UCAD/CN=Recteur UCAD"

# Copy to the SubCA
scp recteur.csr root@192.168.122.40:~/pki/intermediate/csr/
```

### PHASE 5.2 — Issue the Rector's Certificate

Next, let's issue the Rector's certificate for one year:

```bash
openssl ca -config /root/pki/intermediate/intermediate.cnf \
  -extensions recteur \
  -days 365 -notext -md sha256 \
  -engine pkcs11 \
  -keyform engine \
  -keyfile "pkcs11:token=ucad-subca;object=ucad-subca-key;type=private;pin-value=1234" \
  -in ~/pki/intermediate/csr/recteur.csr \
  -out /root/pki/intermediate/certs/recteur.crt

scp /root/pki/intermediate/certs/recteur.crt mrrobot@192.168.122.24:~/certificate
```

---

## PHASE 6 — PDF Signing

In this phase, we will sign a fictional PDF document.

After thoroughly studying the `pyHanko` documentation, I developed the following code:

```python
from pyhanko.sign import pkcs11, signers, timestamps, fields
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from asn1crypto import x509, pem
import asyncio
from pyhanko import stamp
from pyhanko.pdf_utils import text, images
from pyhanko.pdf_utils.font import opentype
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko_certvalidator import ValidationContext

# Function for loading PEM
def pemDecode(cert_path):
    with open(cert_path, "rb") as f:
        pem_byte = f.read()
        _, _, certdata = pem.unarmor(pem_byte)

    return x509.Certificate.load(certdata)

def derRead(cert_path):
    with open(cert_path, "rb") as f:
        cert_bytes = f.read()
    return x509.Certificate.load(cert_bytes)

# Parameters
DOCUMENT_PATH = "/home/mrrobot/certificate/document.pdf"
RCTR_CERT = "/home/mrrobot/certificate/recteur.crt"
INTRMDT_CERT = "/home/mrrobot/certificate/intermediate.crt"
ROOT_CERT = "/home/mrrobot/certificate/root.crt"
MODULE_PATH = "/usr/lib64/softhsm/libsofthsm.so"
SLOT_NO = 0
TOKEN_LABEL = "recteur"
KEY_LABEL = "recteur-key"
PNG_STAMP_PATH = "/home/mrrobot/certificate/ucad.jpg"

# Trust chain for DigiCert's Time Stamp Responder
# Since DigiCert's Root CA is already present in the trust stores,
# we only need to specify the SubCA and the Responder
TSA_CA_CRT = "/home/mrrobot/certificate/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.pem"
TSA_RESPONDER = "/home/mrrobot/certificate/DigiCertSHA512RSA4096TimestampResponder20251.cer"


async def sign():
    # Session initialization
    session = pkcs11.open_pkcs11_session(
        MODULE_PATH,
        slot_no=SLOT_NO,
        token_label=TOKEN_LABEL,
        user_pin="1234"
    )

    # CMS creation
    signer = pkcs11.PKCS11Signer(
        pkcs11_session=session,
        signing_cert=pemDecode(cert_path=RCTR_CERT),
        ca_chain=[pemDecode(INTRMDT_CERT)]
    )

    # Timestamp
    timestmps = timestamps.HTTPTimeStamper("http://timestamp.digicert.com")

    # Validation context providing information required
    # to build the proof of time
    vc = ValidationContext(
        # Include issuers to build the trust chain
        trust_roots=[pemDecode(ROOT_CERT), pemDecode(TSA_CA_CRT)],
        other_certs=[pemDecode(INTRMDT_CERT), derRead(TSA_RESPONDER)],
        # Allow retrieval of revocation information
        allow_fetching=True,
        revocation_mode='hard-fail'
    )

    # Metadata: OCSP-CRL responses, PAdES specification,
    # validation context
    signature_meta = signers.PdfSignatureMetadata(
        field_name='Signature',
        md_algorithm='sha256',

        # Specify the signature as a PAdES signature
        subfilter=SigSeedSubFilter.PADES,

        # Include the validation context
        validation_context=vc,

        # Embed OCSP responses
        embed_validation_info=True,

        # Tell pyHanko to put in an extra DocumentTimeStamp
        # to kick off the PAdES-LTA timestamp chain.
        use_pades_lta=True
    )

    # Signature
    with open(DOCUMENT_PATH, 'rb') as doc:
        w = IncrementalPdfFileWriter(doc)

        fields.append_signature_field(
            w,
            sig_field_spec=fields.SigFieldSpec(
                'Signature',
                # (bottom-left-x, bottom-left-y, top-right-x, top-right-y)
                box=(400, 50, 550, 110)
            )
        )

        out = signers.PdfSigner(
            signature_meta=signature_meta,
            signer=signer,
            timestamper=timestmps,
            stamp_style=stamp.TextStampStyle(
                stamp_text="Signed by: %(signer)s\nTime: %(ts)s",
                background=images.PdfImage(PNG_STAMP_PATH)
            )
        )

        with open("signed.pdf", "wb") as out_file:
            await out.async_sign_pdf(w, output=out_file)


asyncio.run(sign())
```

The code above signs the `document.pdf` file and produces the signed file `signed.pdf` using **PAdES-LTV**.

A **PAdES-LTV** signature embeds within the document the evidence that, at the date and time of issuance, as demonstrated by the OCSP responses, the signer's certificate was valid.

The date and time are provided by a Time Stamping Authority (in this case **DigiCert TSA**) and signed by the TSA, guaranteeing the reliability of the time at which the document was signed.

---

## PHASE 7 — Testing with Adobe

When a recruiter receives a signed diploma, they may not have technical expertise and therefore need an accessible tool to verify its validity.

Adobe is the reference tool because it is widely used in businesses and natively supports the PAdES standard.

We will test the signature's reliability on a Windows client where Adobe has been installed.

First, we need to import the MESRI Root CA certificate.

The MESRI Root CA certificate will allow Adobe to reconstruct the trust chain.

To do this, open Adobe:

- Menu
    
- Preferences
    
- Signatures
    
- Trusted Identities and Certificates > More...
    
- Trusted Certificates > Import
    
- Browse and select the MESRI Root CA certificate
    
- In the Contact section, click the certificate name
    
- Click the certificate in the Certificates section and then click Trust
    
- Check `Use this certificate as a trusted root` and `Certified documents`
    

Then, when we open the `signed.pdf` file and click on the signature:

![/images/Pasted image 20260417000356.png](/images/Pasted%20image%2020260417000356.png)

Open the Signature Panel:

![/images/Pasted image 20260417000331.png](/images/Pasted%20image%2020260417000331.png)

> Since DigiCert's Root CA is already present in Adobe's Trust Store, we do not need to import it manually.

The LAB is validated ✅.

---

## Conclusion

In this lab, I built a PKI infrastructure and implemented **PAdES-LTV** PDF signing.

Through this work, I learned:

- what an **HSM** is and how to interact with it through **PKCS#11**;
    
- how to perform PDF signing with **PyHanko**;
    
- why **PAdES-LTV** is important for diploma signing.
    

However, the lab has some limitations:

- The token PIN is the only security layer protecting the use of the private key in the HSM and is stored in plain text in the signing script's source code;
    
- The use of a software HSM emulator...