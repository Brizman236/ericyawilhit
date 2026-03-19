---
title: "Lab 2 — CRL et OCSP : Implémenter la révocation dans une PKI"
date: 2026-03-19
draft: false
tags:
  - PKI
  - OpenSSL
  - CRL
  - OCSP
  - Lab
description: "Comment implémenter CRL et OCSP dans une PKI complète avec OpenSSL. Révocation de certificats, OCSP Responder et Reverse Proxy Apache."
cover:
  image: "/images/lab2-cover.png"
  alt: "Lab 2 — CRL et OCSP"
  relative: false
---
## Contexte & Objectifs

Dans le [Lab 1](https://github.com/Brizman236/Home-Labs/blob/main/PKI%20TLS%20Lab/Documentation.md),  j'ai configuré une architecture PKI complète comportant une **Root CA**, un **Intermediate CA** et un Seveur WEB utilisant du **HTTPS**. La chaîne de confiance a été validée avec succès depuis un client Windows.

Cependant cette infrastructure présente une **lacune critique** : **absence d'un mécanisme de révocation de certificat**. Dans l'état actuel du Lab, si la clé privée du serveur WEB vient à être compromise avant la date d'expiration, le client fera toujours confiance au certificat si celui-ci n'a pas encore atteint sa date d'expiration. Cela conduira à une attaque de **Man In The Middle**. Non seulement le risque se présente du côté de la clé privée du serveur WEB, mais aussi du côté de celle de l'**Intermediate CA**. De ce fait un mécanisme de **révocation** doit être implémenté pour réduire le risque.

Ce second lab vient combler cette lacune en introduisant les deux mécanismes standards de révocation des certificats :

- **CRL (Certificate Revocation List)** — une liste noire publiée périodiquement par une CA, listant les certificats révoqués
- **OCSP (Online Certificate Status Protocol)** — un service de vérification en temps réel permettant de connaître instantanément le statut d'un certificat

L'implémentation de ces mécanismes nécessite également une refonte de l'architecture PKI existante. En effet, le Lab 1 utilisait la commande `openssl x509` pour signer les certificats — une approche manuelle qui ne tient aucun registre des certificats émis. La révocation exige l'utilisation de `openssl ca`, qui maintient un fichier `index.txt` servant de base de données des certificats et permettant leur révocation.

Ce lab a donc pour objectifs de :
- Reconstruire la PKI avec `openssl ca` pour disposer d'un registre complet
- Configurer le **CDP (CRL Distribution Point)** dans les certificats
- Déployer et tester la **CRL**
- Déployer et tester l'**OCSP Responder**
- Valider la révocation en temps réel depuis le client Windows

___
## Topologie

![Topologie Lab 2](/images/topologie-lab2-crl-ocsp.png)

___
## Configuration Réseau 

|    Machines     | Hostname |       IP       |       Nom de domaine        |
| :-------------: | :------: | :------------: | :-------------------------: |
|     Root CA     |  RootCA  | 192.168.122.20 |      rootca1.cyber.lab      |
| Intermediate CA |  SubCA   | 192.168.122.40 |      subca1.cyber.lab       |
|   Serveur Web   |   web    | 192.168.122.30 | www.cyber.lab crl.cyber.lab |
| Client Windows  |    -     |      DHCP      |              -              |
___

## PHASE 1 : Reconstruction de la PKI

### Phase 1.1 : Création du Root CA

```sh
# Structure des dossiers
mkdir -p ~/pki/root/{private,certs,crl,csr,newcerts}

# Protéger le dossier de la clé privée
chmod 700 ~/pki/root/private

# Registre des certificats émis 
touch ~/pki/root/index.txt

# Numéro de série — commence à 01 
echo 01 > ~/pki/root/serial 

# Numéro de CRL 
echo 01 > ~/pki/root/crlnumber

# Création du fichier de configuration
nano pki/root/root.cnf
```

```ini
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

Le fichier `.cnf` d'une **CA** est sa politique d'émission, il définit tous les types de certificats qu'elle est autorisée à produire. Dans notre cas ici, le fichier `.cnf` définit les extensions pour les certificats du RootCA (`v3_root_ca`) et du SubCA (`v3_intermediate_ca`).
- `crlDistributionPoints`  spécifie l'endpoint duquel l'on peut récupérer le CRL de même que le `authorityInfoAccess` pour le OSCP
- le `keyUsage`  `cRLSign` spécifie que la clé privée de cette autorité peut signer des CRL

Avec le fichier de configuration nous allons maintenant générer la Root CA :
```sh
# Clé privée PEM pass : JG/IpvS3gxqzKg5J
openssl genrsa -aes256 -out ~/pki/root/private/root.key 4096
chmod 400 ~/pki/root/private/root.key

# Certificat auto-signé
openssl req -config ~/pki/root/root.cnf \
  -key ~/pki/root/private/root.key \
  -new -x509 -days 7300 -sha256 \
  -extensions v3_root_ca \
  -out ~/pki/root/certs/root.crt
```

___

### Phase 1.2 : Création de l'Intermediate CA

```sh
# Structure de dossier
mkdir -p ~/pki/intermediate/{private,certs,crl,csr,newcerts}
chmod 700 ~/pki/intermediate/private

touch ~/pki/intermediate/index.txt
echo 01 > ~/pki/intermediate/serial
echo 01 > ~/pki/intermediate/crlnumber

# Création du fichier de configuration
nano ~/pki/intermediate/intermediate.cnf
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

Nous allons maintenant générer la clé privée et le CSR de l'Intermediate CA puis la transférer vers le RootCA :

```sh
# Clé privée Pass PEM : +ptIxeoDsc+kVzer
openssl genrsa -aes256  -out ~/pki/intermediate/private/intermediate.key 4096 
chmod 400 ~/pki/intermediate/private/intermediate.key 

# Générer le CSR 
openssl req -config ~/pki/intermediate/intermediate.cnf -new -sha256 -key ~/pki/intermediate/private/intermediate.key -out ~/pki/intermediate/csr/intermediate.csr

# Copier le CSR vers le rootCA
scp ~/pki/intermediate/csr/intermediate.csr  root@rootca1.cyber.lab:~/
```

Maintenant depuis le Root CA nous allons créer et signer le certificat de l'Intermediate et le lui renvoyer :

```sh
# Création du certificat 
openssl ca -config ~/pki/root/root.cnf \
  -extensions v3_intermediate_ca \
  -days 3650 -notext -md sha256 \
  -in ~/intermediate.csr \
  -out ~/intermediate.crt

# Envoie du certificat à l'intermediate
scp ~/intermediate.crt  root@subca1.cyber.lab:~/pki/intermediate/certs
```

___

### Phase 1.3 : Réémission du certificat du serveur WEB

Précédemment nous avions généré la clé privée du serveur web dans `/etc/ssl/lab/private` et les CSR dans `/etc/ssl/lab/webserver.csr`. Maintenant nous allons transférer ce CSR sur le SubCA et émettre le certificat du serveur web :

```sh
scp /etc/ssl/lab/webserver.csr root@subca1.cyber.lab:~/

# Sur le SubCA
openssl ca -config ~/pki/intermediate/intermediate.cnf \
  -extensions server_cert \
  -days 365 -notext -md sha256 \
  -in ~/webserver.csr \
  -out ~/webserver.crt
  
# Création de la chaîne de confiance
cat ~/pki/intermediate/certs/intermediate.crt webserver.crt > ca-chain

# Transfert du certificat et de la chaîne de confiance sur le Serveur WEB
scp webserver.crt root@www.cyber.lab:/etc/ssl/lab/certs/
scp ca-chain.crt root@www.cyber.lab:/etc/ssl/lab/certs/
```

___

## PHASE 2 : CRL & OCSP

Durant les précédentes configurations, nous avions émis les certificats avec leur **CRL Distribution Points** (CDP) et l'endpoint du OCSP Responder, chaque certificat est émis avec le CDP contenant le CRL de son signataire.
Dans cette phase nous allons créer et configurer le serveur WEB à ce qu'il héberge les CRL et l'OCSP Responder, générer le CRL du SubCA  configurer le OCSP Responder et faire un test de révocation.

___

#### **Configuration du serveur web**

Les CRLs seront hébergées sur le nom de domaine `crl.cyber.lab`, enregistrons donc ce nom sur le serveur DNS :

![Configuration DNS](/images/Pasted%20image%2020260312101209.png)

Maintenant nous allons créer un VirtualHost qui va héberger le site des CRLs et l'OSCP :

```sh
# Sur le serveur WEB
mkdir -p /var/www/crl/crl
mkdir -p /var/www/crl/ocsp/root
mkdir -p /var/www/crl/ocsp/intermediate

# Création du VirtualHost
nano /etc/apache2/sites-available/crl.conf
```

```cnf
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

```sh
# Activation du Site
a2ensite crl.conf
systemctl reload apache2
```

![Pasted image 20260312102625](/images/Pasted%20image%2020260312102625.png)
#### Génération du CRL sur le SubCA

```sh
openssl ca -config ~/pki/intermediate/intermediate.cnf \
  -gencrl \
  -out ~/pki/intermediate/crl/intermediate.crl
  
# Puis lisons cette crl avec 
openssl crl -in ~/pki/intermediate/crl/intermediate.crl -text
```

La CRL est générée et signée avec la clé du SubCA pour prouver sa validité. Aucun certificat n'est encore révoqué comme nous pouvons le voir 👇

![Vérification CRL](/images/Pasted%20image%2020260312102146.png)

___

#### Configuration du OCSP Responder

L'OCSP Responder a pour rôle d'assurer la vérification en temps réel du statut d'un certificat. Ce dernier signe ses réponses pour empêcher une attaque de Man In The Middle. 

Lorsque le client part sur le site web, il vérifie la validité de toute la chaîne de confiance en commençant par l'Intermediate et ensuite le certificat du serveur WEB. 

Nous allons configurer deux OCSP Responders, un hébergé sur le RootCA chargé de répondre à la vérification du SubCA et un autre hébergé sur le SubCA pour le certificat Serveur.

> NB : En production, les OCSP Responder sont délégués à un serveur dédié

**OSCP Responder sur SubCA**

```sh
# Clé privée
openssl genrsa -out ~/pki/intermediate/private/ocsp.key 4096 
chmod 400 ~/pki/intermediate/private/ocsp.key

# CSR
openssl req -new \ -key ~/pki/intermediate/private/ocsp.key \ -out ~/pki/intermediate/csr/ocsp.csr \ -subj "/C=SN/ST=Senegal/O=Cyber Lab/CN=OCSP Responder"

# Emission du certificat
openssl ca -config ~/pki/intermediate/intermediate.cnf \
  -extensions ocsp \
  -days 365 -notext -md sha256 \
  -in ~/pki/intermediate/csr/ocsp.csr \
  -out ~/pki/intermediate/certs/ocsp.crt
```

**OCSP Responder sur Root CA**

```sh
# Clé privée
openssl genrsa -out ~/pki/root/private/ocsp.key 4096 
chmod 400 ~/pki/root/private/ocsp.key

# CSR
openssl req -new  -key ~/pki/root/private/ocsp.key -out ~/pki/root/csr/ocsp.csr  -subj "/C=SN/ST=Senegal/O=Cyber Lab/CN=OCSP Responder RootCA"

# Emission du certificat
openssl ca -config ~/pki/root/root.cnf \
  -extensions ocsp \
  -days 365 -notext -md sha256 \
  -in ~/pki/root/csr/ocsp.csr \
  -out ~/pki/root/certs/ocsp.crt
```

L'OCSP responder est un service qui tournera en permanence à travers un port d'écoute. Cependant nous avons spécifié l'endpoint sur le serveur WEB, la question qui se pose c'est comment la requête du client qui se fera en direction du serveur web pourra atteindre le SubCA ?

Pour cela nous allons utiliser un **Reverse Proxy**  qui redirigera la requête vers le SubCA et le Root CA les gardant isolés.

Lançons tout d'abord les OCSP Responder :

```sh
# Sur le RootCA
openssl ocsp \
  -port 2560 \
  -text \
  -index ~/pki/root/index.txt \
  -CA ~/pki/root/certs/root.crt \
  -rkey ~/pki/root/private/ocsp.key \
  -rsigner ~/pki/root/certs/ocsp.crt \
  -out ~/ocsp.log &

# Sur le SubCA
openssl ocsp \
  -port 2560 \
  -text \
  -index ~/pki/intermediate/index.txt \
  -CA ~/pki/intermediate/certs/intermediate.crt \
  -rkey ~/pki/intermediate/private/ocsp.key \
  -rsigner ~/pki/intermediate/certs/ocsp.crt \
  -out ~/ocsp.log &
```

Ensuite configurons le Reverse Proxy sur le Web Server :

```sh
# Activation des modules nécessaires
a2enmod proxy proxy_http
systemctl restart apache2

# Modification de crl.cnf
nano /etc/apache2/sites-available/crl.conf
```

```cnf       
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

Quand une requête se fera en direction de `/ocsp/intermediate` elle sera rediriger vers `http://subca1.cyber.lab:2560`,  ensuite quand le SubCA va répondre, le Proxy remplacera l'URL contenu dans le Header par le sien `crl.cyber.lab`. Le même principe s'applique à une requête sur l'endpoint `/ocsp/root`. Redémarrons le service `apache2`.

___

Testons le OCSP Responder depuis le RootCA :

```sh
openssl ocsp   -issuer ~/intermediate.crt   -cert ~/webserver.crt   -url http://crl.cyber.lab/ocsp/intermediate -CAfile ~/pki/root/certs/root.crt

openssl ocsp   -issuer ~/pki/root/certs/root.crt   -cert ~/intermediate.crt   -url http://crl.cyber.lab/ocsp/root   -CAfile ~/pki/root/certs/root.crt
```

![Test OCSP Responder SubCA](/images/Pasted%20image%2020260315095846.png)

![Test OCSP Responder Root CA](/images/Pasted%20image%2020260315095804.png)
___

#### **Test de révocation**

Nous allons maintenant révoquer le certificat du serveur WEB depuis le SubCA et regénérer le CRL :

```sh
openssl ca -config ~/pki/intermediate/intermediate.cnf -revoke ~/pki/intermediate/newcerts/01.pem

# Génération du CRL
openssl ca -config ~/pki/intermediate/intermediate.cnf \
  -gencrl \
  -out ~/pki/intermediate/crl/intermediate.crl

# Copie du CRL sur le Serveur WEB
scp ~/pki/intermediate/crl/intermediate.crl root@www.cyber.lab:/var/www/crl/crl
```

En refaisant la requête OCSP depuis le RootCA, nous obtenons une réponse disant que le Certificat a été révoqué :

![Test de Révocation](/images/Pasted%20image%2020260312111709.png)

Sur le navigateur du client, la révocation n'est pas détecté. Pourquoi ?
Pour en comprendre la raison, définissons d'abord la différence entre une **PKI publique** et une **PKI privée**.

___

#### PKI publique & PKI privée

Une **PKI publique** dispose d'une CA **mondialement connu** comme **DigiCert** ou **Let's Encrypt** et incluse dans les Trusts Store (Google, Mozilla, etc). Le Root CA est pré-installé sur l'OS et dans le navigateur. 

Une **PKI privée**, quant à elle, est celle disposant d'une **CA** généré par une organisation pour ses activités propres. Le Root CA ici n'est pas inclus dans les Trusts Store.

Dans les navigateurs, principalement dans **Google Chrome**, il est installé une base de données de CRLs collectées par Google distribuées à chaque mise à jour de Google Chrome. On appelle cette base de données un **CRLSet**. La révocation est donc vérifiée en local par le navigateur sans faire des requêtes sur le réseau. 

> C'est pourquoi le navigateur de notre client n'a pas détecté la révocation.


