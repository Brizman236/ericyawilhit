---
title: "Implémenter une PKI avec SoftHSM2 et PAdES : Sécuriser la délivrance des diplômes universitaires avec PyHanko"
date: 2026-04-17
draft: false
description: Face au fléau de la falsification des diplômes, ce guide technique détaille la mise en place d'une infrastructure de confiance (PKI) souveraine. À travers un laboratoire pratique utilisant SoftHSM2, OpenSSL et PyHanko, découvrez comment la signature numérique PAdES-LTV permet de garantir l'authenticité et l'intégrité des titres universitaires, vérifiables instantanément par les recruteurs via Adobe Acrobat
cover:
  image: /images/lab3-cover.jpg
  alt: Signature numérique de diplômes
  relative: false
---


## Contexte & Objectifs

Dans le secteur universitaire et sur le marché de l'emploi en Afrique, l'on déplore une falsification massive des diplômes. Cela est dû à un manque d'infrastructure fiable pouvant servir à la vérification de la validité des diplômes délivrés par les Universités et Ecoles Africaines.

Avec la PKI, cette infrastructure de vérification est réalisable en utilisant la **signature numérique**. 
Comment la signature numérique peut-elle empêcher la falsification des diplômes ? Comment reconnaître la validité d'un diplôme signé numériquement ?

La falsification de diplôme survient lorsqu'un *diplômé* souhaite postuler à un emploi ou candidater à une formation. Dans ce scénarion nous avons 2 acteurs concerné : l'université qui a délivré le diplôme, le responsable de recrutement qui reçoit le diplôme. Comment ce dernier pourrait faire confiance au diplôme présenté par l'étudiant ? Comment peut-il en attesté la validité ?

Pour ce faire il faut qu'il ait une entité tierce reconnue comme autorité de confiance par le reponsable de recrutement. Cette entité (le MESRI pour Ministère de l'Enseignement Supérieur, de la Recherche et de l'Innovation au Sénégal)  ne signera pas les diplômes directement, son rôle sera de certifier l'identité de l'Université, ce qui garantit :
- que la signature posée sur le diplôme provient bien de l'Université en question et non à un tier malveillant
- l'intégrité du document car la signature se retrouverait invalide s'il y a modification
- La non-répudiation : l'université ne peut nier avoir signé/délivré le diplôme
Le recruteur n'aura pas à contacter l'Université pour vérfication, le certificat de l'université est embarqué dans le PDF, Adobe Acrobat l'extrayera et fera la vérification automatiquement puis remontera la chaîne de confiance jusqu'au MERSI

L'on sait que les certificats ont tous une date d'expiration, de ce fait, l'on ne saurait vérifier la validité d'un diplôme si le certificat du signataire expire, de même si sa clé privée utilisé pour signer le document se retrouve compromise. Comment préserver la validité d'un diplôme dans ces deux cas ? Quand est-ce que la signature doit être valide ?

La signature numérique ne doit pas être valide au moment de la vérification mais plutôt au moment de l'émission. Ce que résout le **PAdES-LTV** que nous détaillerons plutard.

Pour implémenter cettre infrastructure de confiance, nous adopterons la hiérarchie suivante :
- une Root CA qui est le MESRI
- une SubCA représentant l'Université (dans notre ca l'UCAD)
- la personne habiletée à signer les diplômes dans l'université, nous prendrons le Recteur

Dans le lab nous allons implémenter :
- une PKI avec **SoftHSM2**
- un **certificat de signature** pour le Recteur
- la Signature PDF avec PyHanko (PAdES)
- la vérification avec Adobe Acrobat Reader

**Objectifs d'apprentissage**
- Comprendre PKCS#11 avec SoftHSM2
- Implémenter PAdES
- Cas d'usage concret - souveraineté numérique

____

## Topologie

![/images/lab3-topologie.jpg](/images/lab3-topologie.jpg)

___

## Configuration réseau

| Machine      | Rôle            | OS            | HSM      | IP             | FQDN              |
| ------------ | --------------- | ------------- | -------- | -------------- | ----------------- |
| `mesri-ca`   | Root CA         | Ubuntu Server | SoftHSM2 | 192.168.122.20 | rootca1.cyber.lab |
| `ucad-ca`    | Intermediate CA | Ubuntu Server | SoftHSM2 | 192.168.122.40 | subca1.cyber.lab  |
| `recteur`    | Signataire PDF  | Fedora        | SoftHSM2 | DHCP           | —                 |
| `dns`        | DNS             | Ubuntu Server | —        | 192.168.122.10 | dns.cyber.lab     |
| `client`     | Adobe Reader    | Windows 10    | —        | DHCP           | —                 |
| `crl-server` | Révocation      | Ubuntu Server | SoftHSM2 | 192.168.122.30 | crl.cyber.lab     |

___

## PHASE 1 : Installation des outils

Dans ce lab nous avons besoins de :
- **OpenSSL CA**
- **SoftHSM2** : il simule un module matériel sécurisé en stockant des clés privées dans une base de données chiffrées sur le Disque. Il va stocker les clés privées hors du filesystem classique.
- **GnuTLS** : une suite d'outils cryptographique notament `p11tool` pour intéragir avec les tokens PKCS#11. Il est utilisé pour lister, inspecter et vérifier des clés privées stockées dans le SoftHSM2
- **libengine-pkcs11-openssl** : Plugin PKCS#11 pour OpenSSL, il permet à OpenSSL de déléguer les opérations cryptographiques à un token PKCS#11 comme SoftHSM2. 
- **PyHanko** : Bibliothèque Python spécialisée dans la signature PDF, elle supporte PAdES, LTV, timestamps
- **Opensc** : Suite d'outils pour smartcards et tokens PKCS#11, fournit `pkcs11-tool` pour interagir avec SoftHSM2.Il sera utilisé pour générer les paires de clés dans le SoftHSM.
- **python-pkcs11**: Librairie python permettant d'utiliser PKCS#11

Pour les intaller nous allons taper ces commandes :

Sur le RootCA et le SubCA, :
```sh
apt update & apt install -y openssl softhsm2 gnutls-bin libengine-pkcs11-openssl opensc
```

Sur le Serveur de Révocation :
```sh
apt update & apt install -y apache2
```

Sur Fedora :
```sh
sudo dnf update -y
sudo dnf install -y softhsm opensc gnutls-utils python3-pip libengine-pkcs11-openssl
pip install 'pyHanko[pkcs11,image-support,opentype,qr]'
pip install pyhanko-cli python-pkcs11
```

___
## PHASE 2 : PKI MESRI (Root CA)
### Phase 2.1 - Initialiser SoftHSM2 sur le Root CA
Nous allons initialiser un **token** dans le SoftHSM2 du RootCA. Un token est une instance logique du HSM qui peut contenir des objects cryptographiques (clés privées, clés publiques, certificats, données secrètes) dans notre cas ici la clé privée du Root CA. 
Il dispose :
- Un Label / nom
- Un PIN utilisateur : utilisé pour manipuler les objets qui y sont stockées
- Un SO PIN pour l'administrateur
Initialisons notre token avec :

```sh
softhsm2-util --init-token --slot 0 --label "mesri-root" --pin 1234 \ --so-pin 2468
```

![/images/Pasted image 20260321010741.png](/images/Pasted%20image%2020260321010741.png)

Le slot (emplacement physique ou logique où un token est inséré) a été réinitialisé à `1893920401`

___
### PHASE 2.2 : Générer la clé privée du Root CA dans SoftHSM2

Nous allons utiliser l'outil `pkcs11-tool` en spécifiant le la bibliothèque **PKCS#11** du SoftHSM `/usr/lib/softhsm/libsofthsm2.so`. C'est un outil générique, et ne sait pas quel HSM l'on utilise c'est pourquoi il faut la spécifier.

```sh
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen \
  --key-type rsa:4096 \
  --label "mesri-root-key" \
  --token-label "mesri-root"
```

![/images/Pasted image 20260321012220.png](/images/Pasted%20image%2020260321012220.png)

Vérifions le contenu du token pour voir si la paire de clés y est avec :

```sh
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --list-objects \
  --token-label "mesri-root"
```

![/images/Pasted image 20260321012600.png](/images/Pasted%20image%2020260321012600.png)

___
### PHASE 2.3 - Création du certificat Root CA
Tout d'abord nous allons créer la structure du dossier du Root CA :
```sh
mkdir -p /root/pki/root/{certs,crl,csr,newcerts}
touch /root/pki/root/index.txt
echo 01 > /root/pki/root/serial
echo 01 > /root/pki/root/crlnumber
```

Puis le fichier de configuration `/root/pki/root/root.cnf` :

```ini
[ ca ]
default_ca = CA_default
# Point d'entrée principal — dit à OpenSSL quelle section
# utilise comme configuration par défaut
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
# Répertoires de travail
dir               = /root/pki/root
# Répertoire racine de la PKI Root CA

certs             = $dir/certs
# Stocke les certificats émis

crl_dir           = $dir/crl
# Stocke les CRLs générées

new_certs_dir     = $dir/newcerts
# Archive une copie de chaque certificat signé
# nommée par son numéro de série

database          = $dir/index.txt
# Registre de tous les certificats émis
# Format : Status | Expiry | Serial | DN

serial            = $dir/serial
# Fichier contenant le prochain numéro de série
# Incrémenté automatiquement à chaque signature

crlnumber         = $dir/crlnumber
# Numéro de la prochaine CRL générée

private_key       = $dir/private/root.key
# On ne mettra rien ici — la clé est dans SoftHSM2
# On utilisera une URI PKCS#11 à la place

certificate       = $dir/certs/root.crt
# Certificat auto-signé du Root CA

crl               = $dir/crl/root.crl
# CRL courante du Root CA

default_md        = sha256
# Algorithme de hachage — SHA256 est le standard actuel

default_days      = 3650
# Durée de validité des certificats émis — 10 ans

default_crl_days  = 30
# Durée de validité d'une CRL — 30 jours

policy            = policy_strict
# Politique de validation des CSR

[ policy_strict ]
# Champs obligatoires et leurs contraintes
# match   = doit correspondre exactement au Root CA
# supplied = doit être fourni dans le CSR
# optional = peut être absent
countryName             = supplied
stateOrProvinceName     = supplied
organizationName        = supplied
commonName              = supplied

[ req ]
default_bits        = 4096
# Taille de clé par défaut — 4096 bits pour Root CA

prompt              = no
# Ne pas demander interactivement les champs DN

default_md          = sha256
distinguished_name  = dn

[ dn ]
# Distinguished Name du Root CA
C  = SN
# Sénégal

ST = Senegal
O  = MESRI
# Ministère de l'Enseignement Supérieur

CN = MESRI Root CA
# Nom qui apparaîtra dans les certificats

[ v3_ca ]
# Extensions appliquées au certificat Root CA
basicConstraints = critical, CA:true
# Cette entité EST une CA
# critical = le client doit comprendre cette extension

keyUsage = critical, keyCertSign, cRLSign
# keyCertSign = peut signer des certificats
# cRLSign     = peut signer des CRLs

subjectKeyIdentifier = hash
# Empreinte de la clé publique
# Permet d'identifier la clé dans la chaîne

authorityKeyIdentifier = keyid:always, issuer
# Référence à la clé qui a signé ce certificat
# Pour Root CA = se référence lui-même

[ v3_intermediate_ca ]
# Extensions appliquées au certificat Intermediate CA
basicConstraints = critical, CA:true, pathlen:0
# CA:true   = c'est une CA
# pathlen:0 = ne peut pas créer de Sub-CA en dessous
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
crlDistributionPoints = URI:http://crl.cyber.lab/crl/root.crl
authorityInfoAccess = OCSP;URI:http://crl.cyber.lab/ocsp/root
# Le client cherche la CRL du Root CA ici

[ ocsp ]
# Extensions pour le certificat OCSP Responder du Root CA
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
# Autorise explicitement ce certificat à signer
# des réponses OCSP
subjectKeyIdentifier = hash
noCheck = ignored
# RFC 6960 — dit au client de ne pas vérifier
# la révocation de CE certificat OCSP
# évite la boucle infinie de vérification
```

Pour pouvoir générer le certificat du Root CA, nous devons tout d'abord récupérer l'URI PKCS#11 de la clé en listant les objets du token `mesri-root` avec `p11tool` de GnuTLS :

```sh
p11tool --list-all --login "pkcs11:token=mesri-root" --provider /usr/lib/softhsm/libsofthsm2.so
```
 
```text
pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=cdb4e58ef0e2ee91;token=mesri-root;object=mesri-root-key;type=private
```

Puis l'utiliser pour créer le certificat :

```sh
openssl req -new -x509 \
  -engine pkcs11 \
  -keyform engine \
  -key "pkcs11:token=mesri-root;object=mesri-root-key;type=private;pin-value=1234"\
  -config /root/pki/root/root.cnf \
  -extensions v3_ca \
  -days 7300 \
  -sha256 \
  -out /root/pki/root/certs/root.crt
```

___
### PHASE 2.4 — Générer la CRL initiale du Root CA

```sh
openssl ca -config /root/pki/root/root.cnf \
  -gencrl \
  -keyfile "pkcs11:token=mesri-root;object=mesri-root-key;type=private;pin-value=1234" \
  -keyform engine \
  -engine pkcs11 \
  -out /root/pki/root/crl/root.crl
```

Nous avons fini avec la création du Root CA, passons maintenant à celle du SubCA (l'Université nous prendrons UCAD).

___

## PHASE 3 - SubCA UCAD

La configuration du SubCA sera presque identique à celle du Root CA, la différence se portera sur la signature du certificat qui devra se faire sur le Root CA. Tout d'abord, créeons la structure des dossiers et le fichier de configuration:

```sh
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

___

### PHASE 3.1 — Initialiser SoftHSM2 sur le SubCA 

Nous allons créer un token avec le nom `ucad-intermediate` :

```sh
softhsm2-util --init-token --slot 0 --label "ucad-subca" --pin 1234 --so-pin 5678
```

**Générer la clé privée du SubCA dans SoftHSM2**

```sh
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen \
  --key-type rsa:4096 \
  --label "ucad-subca-key" \
  --token-label "ucad-subca"
```


### PHASE 3.2 Génération du CSR du SubCA et émission de son certificat

```sh
openssl req -new \
  -engine pkcs11 \
  -keyform engine \
  -key "pkcs11:token=ucad-subca;object=ucad-subca-key;type=private;pin-value=1234"\
  -config /root/pki/intermediate/intermediate.cnf \
  -out /root/pki/intermediate/csr/intermediate.csr
```

#### Emission du certificat du SubCA
Après avoir copié le CSR sur le Root CA, nous allons utiliser `openssl ca` pour émettre le certificat du SubCA :

```sh
openssl ca -config /root/pki/root/root.cnf \
  -extensions v3_intermediate_ca \
  -days 3650 -notext -md sha256 \
  -engine pkcs11 \
  -keyform engine \
  -keyfile "pkcs11:token=mesri-root;object=mesri-root-key;type=private;pin-value=1234" \
  -in ~/ucad-subca.csr \
  -out ~/intermediate.crt

# Copie des certificats de MESRI et de UCAD sur le SubCA
scp intermediate.crt  root@subca1.cyber.lab:~/
```

___
### PHASE 4 : Le serveur de révocation

Il sera utilisé dans notre lab pour exposer les endpoints de révocations ( CRLs, OCSP Responders)via HTTP (Apache). En production l'on utilise un serveur dédié pour héberger les OCSP Responders, gardant le Root CA isolé. Dans notre lab nous allons démarrer les OCSP Responders sur le Root et le Sub CA, utilisé un Reverse Proxy sur le serveur de révocation pour les garder isolés. Les CRLs seront émises et déployées sur le Serveur via `scp`. 

### PHASE 4.1 : Émission des certificats des OCSP Responders

Nous avons deux OCSP Responders, un sur le Root CA et l'autre sur le Sub CA. Tout d'abord nous allons généré leur clés privées dans les SoftHSM2s :

```sh
# Sur le Root CA
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen \
  --key-type rsa:4096 \
  --label "mesri-ocsp-key" \
  --token-label "mesri-root"

# Sur le Sub CA
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen \
  --key-type rsa:4096 \
  --label "ucad-ocsp-key" \
  --token-label "ucad-subca"
```

Ensuite générons les CSRs et émettons les certificats :

```sh
# Sur le Root CA
openssl req -new \
  -engine pkcs11 \
  -keyform engine \
  -key "pkcs11:token=mesri-root;object=mesri-ocsp-key;type=private;pin-value=1234"\
  -subj "/C=SN/ST=Senegal/O=MESRI /CN=MESRI OCSP Responder"
  -out /root/pki/root/csr/ocsp-root.csr

openssl ca -config /root/pki/root/root.cnf \
  -extensions ocsp \
  -days 365 -notext -md sha256 \
  -engine pkcs11 \
  -keyform engine \
  -keyfile "pkcs11:token=mesri-root;object=mesri-root-key;type=private;pin-value=1234" \
  -in /root/pki/root/csr/ocsp-root.csr \
  -out /root/pki/root/certs/ocsp-root.crt
  
# Sur le Sub CA  
openssl req -new \
  -engine pkcs11 \
  -keyform engine \
  -key "pkcs11:token=ucad-subca;object=ucad-ocsp-key;type=private;pin-value=1234"\
  -subj "/C=SN/ST=Senegal/O=UCAD /CN=UCAD OCSP Responder" \
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

___

### PHASE 4.2 : Configuration d'Apache

Nous allons créer et configurer un VirtualHost qui va exposer nos endpoints. 

**Créations des dossiers de notre serveur :**
```sh
mkdir -p /var/www/revoke/crl
mkdir -p /var/www/revoke/ocsp/{root,intermediate}
```

**Fichier de configuration du Virtualhost dans `/etc/apache2/sites-available/revoke.conf`**
```ini
<VirtualHost *:80>
    ServerName crl.cyber.lab
    DocumentRoot /var/www/revoke

    <Directory /var/www/revoke>
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

**Activation des modules nécessaires et du site :**
```sh
a2enmod proxy proxy_http
a2ensite revoke.conf
systemctl reload apache2
```

Pour pouvoir utiliser pkcs#11 pour démarrer un OCSP Responder, il faut tout d'abord créer le provider pkcs11 dans le fichier de configuration d'OpenSSL `/etc/ssl/openssl.cnf`.
Pour ce faire nous devons tout d'abord installer le paquet `pkcs11-provider` avec `apt install -y pkcs11-provider`, ensuite modifier `openssl.cnf` :

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

**Démarrage des OCSP Responders :**
```sh
 # Sur le RootCA
openssl ocsp \
  -port 2560 \
  -text \
  -index ~/pki/root/index.txt \
  -CA ~/pki/root/certs/root.crt \
  -rkey "pkcs11:token=mesri-root;object=mesri-ocsp-key;type=private;pin-value=1234" \
  -rsigner ~/pki/root/certs/ocsp-root.crt \
  -out ~/ocsp.log &

# Sur le SubCA
openssl ocsp \
  -port 2560 \
  -text \
  -index ~/pki/intermediate/index.txt \
  -CA ~/pki/intermediate/certs/intermediate.crt \
  -rkey "pkcs11:token=ucad-subca;object=ucad-ocsp-key;type=private;pin-value=1234" \
  -rsigner ~/pki/intermediate/certs/ocsp-ucad.crt \
  -out ~/ocsp.log &
```

Pour éviter l'erreur `No CKA_ID in source object`, nous devons attribuer les mêmes IDs aux clés de chaque OCSP Responder :

```sh
# Sur le Root CA
p11tool --login "pkcs11:token=mesri-root;object=mesri-ocsp-key;type=private;pin-value=1234" --set-id=01
p11tool --login "pkcs11:token=mesri-root;object=mesri-ocsp-key;type=public;pin-value=1234" --set-id=01

# Sur le Sub CA
p11tool --login "pkcs11:token=ucad-subca;object=ucad-ocsp-key;type=private;pin-value=1234" --set-id=02
p11tool --login "pkcs11:token=ucad-subca;object=ucad-ocsp-key;type=public;pin-value=1234" --set-id=02
```

**Génération et publication des CRLs**

```sh
# Sur le Root CA
openssl ca -config /root/pki/root/root.cnf \
  -gencrl \
  -keyfile "pkcs11:token=mesri-root;object=mesri-root-key;type=private;pin-value=1234" \
  -keyform engine \
  -engine pkcs11 \
  -out /root/pki/root/crl/root.crl
scp /root/pki/root/crl/root.crl root@192.168.122.30:/var/www/revoke/crl/

# Sur le Sub CA
openssl ca -config /root/pki/intermediate/intermediate.cnf \
  -gencrl \
  -keyfile "pkcs11:token=ucad-subca;object=ucad-subca-key;type=private;pin-value=1234" \
  -keyform engine \
  -engine pkcs11 \
  -out /root/pki/intermediate/crl/intermediate.crl
scp /root/pki/intermediate/crl/intermediate.crl root@192.168.122.30:/var/www/revoke/crl/
```

___
## PHASE 5 - Certificat du Recteur

Le Recteur a besoin d'une identité numérique pour pouvoir signer les diplômes. Elle est composée de deux éléments indispensables :
- La clé privée : stockée dans le SoftHSM et ne sort jamais
- Le certificat du recteur émis par UCAD SubCA avec l'extension requise pour la signature 

Pour créer cette identité numérique, nous allons :
- Générer la clé privée du recteur dans le SoftHSM et du CSR
- Créer un template pour le certificat sur le SubCA et émettre le certificat du recteur
- Configurer pyHanko pour qu'il utilise la clé privée et le certificat pour signer les PDF

### PHASE 5.1 : Génération de la clé privée dans le SoftHSM du recteur

SoftHSM par défaut ne peut être utilisé qu'en mode root, nous allons créer une config utilisateur pour permettre au Recteur d'utiliser sa clé privée.

```sh
mkdir -p ~/.config/softhsm2
mkdir -p ~/.softhsm2/tokens

cat > ~/.config/softhsm2/softhsm2.conf << EOF
directories.tokendir = $HOME/.softhsm2/tokens/
objectstore.backend = file
EOF

export SOFTHSM2_CONF=~/.config/softhsm2/softhsm2.conf
```
Les tokens de l'utilisateur seront stockés dans `~/.softhsm2/tokens`
Initialisation du token 
```sh
softhsm2-util --init-token --slot 0 --label "recteur" --pin 1234 --so-pin 5678
```

Génération des clés
```sh
pkcs11-tool --module /usr/lib64/softhsm/libsofthsm.so --login --token-label "recteur" --pin 1234 --keypairgen --key-type rsa:2048 --label "recteur-key"
```

Génération du CSR
```sh
openssl req -new \
  -engine pkcs11 \
  -keyform engine \
  -key "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=247e8903bf1b2f9e;token=recteur;object=recteur-key;type=public?pin-value=1234" \
  -out ~/recteur-diallo.csr \
  -subj "/C=SN/ST=Senegal/O=UCAD/CN=Recteur UCAD"
# Copie sur le subca
scp recteur.csr root@192.168.122.40:~/pki/intermediate/csr/
```

### PHASE 5.2 - Émission du certificat du recteur

Ensuite émettons le certificat du recteur pour 1 an:
```sh
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

___

## PHASE 6 : Signature PDF

Dans cette phase nous allons signé un document PDF Fictif. Après une lecture approfondie de la documentation du `pyhanko`, j'ai pu développer ce bout de code.

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

# Fonction pour charger du PEM
def pemDecode(cert_path):
    with open(cert_path, "rb") as f:
        pem_byte = f.read()
        _,_, certdata = pem.unarmor(pem_byte)
    
    return x509.Certificate.load(certdata)

def derRead(cert_path):
    with open(cert_path, "rb") as f:
        cert_bytes = f.read()
    return x509.Certificate.load(cert_bytes)

# Paramètre
DOCUMENT_PATH = "/home/mrrobot/certificate/document.pdf"
RCTR_CERT = "/home/mrrobot/certificate/recteur.crt"
INTRMDT_CERT = "/home/mrrobot/certificate/intermediate.crt"
ROOT_CERT = "/home/mrrobot/certificate/root.crt"
MODULE_PATH = "/usr/lib64/softhsm/libsofthsm.so"
SLOT_NO = 0
TOKEN_LABEL = "recteur"
KEY_LABEL = "recteur-key"
PNG_STAMP_PATH = "/home/mrrobot/certificate/ucad.jpg"

# Chaîne de confiance pour le Time Stamp Responder de DigiCert
# Puisque le RootCA de DigiCert figure déjà dans les Trust Stores, nous n'allons que spécifier
# le Sub CA et le Responder 
TSA_CA_CRT = "/home/mrrobot/certificate/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.pem"
TSA_RESPONDER = "/home/mrrobot/certificate/DigiCertSHA512RSA4096TimestampResponder20251.cer"


async def sign():
    # Initialisation de la session
    session = pkcs11.open_pkcs11_session(MODULE_PATH, slot_no=SLOT_NO, token_label=TOKEN_LABEL, user_pin="1234")

    # Créations du CMS
    signer = pkcs11.PKCS11Signer(pkcs11_session=session, signing_cert=pemDecode(cert_path=RCTR_CERT), ca_chain=[pemDecode(INTRMDT_CERT)])

    # Timestamp
    timestmps = timestamps.HTTPTimeStamper("http://timestamp.digicert.com")
    
	# Le contexte de Validation fournissant les informations pour la
    # constitution de la preuve de temps
    vc = ValidationContext(
        # Inclusion des Issuers pour la constitution de la chaîne de confiance
        trust_roots=[pemDecode(ROOT_CERT), pemDecode(TSA_CA_CRT)],
        other_certs = [pemDecode(INTRMDT_CERT), derRead(TSA_RESPONDER)],
        # Autoriser la récupération des informations de révocation
        allow_fetching=True, 
        revocation_mode='hard-fail'
    )
    # Les métadonnées : réponses OCSP-CRL, Spécification de la norme PAdES, contexte
    # de validation
    signature_meta = signers.PdfSignatureMetadata(
        field_name='Signature', md_algorithm='sha256',
        # Spécifier la signature comme une signature PAdES
        subfilter=SigSeedSubFilter.PADES,
        # Inclure le contexte de validation 
        validation_context=vc,
        # Embarquer les réponses OCSP
        embed_validation_info=True,
        # Tell pyHanko to put in an extra DocumentTimeStamp
        # to kick off the PAdES-LTA timestamp chain.
        use_pades_lta=True
    )

    # La signature 
    with open(DOCUMENT_PATH, 'rb') as doc:
        w = IncrementalPdfFileWriter(doc)
        fields.append_signature_field(
    w, sig_field_spec=fields.SigFieldSpec('Signature', 
        # (x_bas_gauche, y_bas_gauche, x_haut_droit, y_haut_droit)
        box=(400, 50, 550, 110) 
    )
)
        out = signers.PdfSigner(
            signature_meta=signature_meta,
            signer=signer, timestamper=timestmps, 
            stamp_style=stamp.TextStampStyle(
                stamp_text="Signé par : %(signer)s\nTime: %(ts)s",
                background=images.PdfImage(PNG_STAMP_PATH)
            )
        )
        with open("signed.pdf", "wb") as out_file:
            await out.async_sign_pdf(w, output=out_file)
        
        
asyncio.run(sign())
```

Le code ci-dessus fait la signature du PDF  `document.pdf` et délivre le fichier signé `signed.pdf` avec **PAdES-LTV**. Une signature `PAdES-LTV` embarque dans le document la preuve qu'à la date et l'heure de l'émission grâce aux réponses OCSP, le certificat du signataire a été valide. La date et l'heure ont été délivrées par une autorité d'horodatage (ici **DigiCert TSA**) et signées par cette dernière garantissant la fiabilité de l'heure à laquelle le document a été signé.

___

## PHASE 7 : Test avec Adobe

Lorsqu'un recruteur recoit un diplome signé, n'ayant pas de compétences technique, il a besoin d'un outil accessible lui permettant de vérifier la validiter. Adobe est l'outil de reférence car il est très utilisé en entreprise et supporte nativement le standard PAdES.

Nous allons tester la fiabilité de la signature sur Un client Windows où Adobe a été installé. Tout d'abord nous devons importer le certificat de MESRI Root CA. Le MESRI RootCA Certificate permettra à Adobe de reconstruire la chaine de confiance.
Pour ce faire, ouvrons Adobe :
- Menu
- Préférences
- Signatures
- Identités et Certificats approuvés > Autres ...
- Certificats approuvés > Bouton importé
- Parcourir et sélectioner le certificat de MESRI Root CA
- Dans la section Contact, cliquer sur le nom du certificat  
- Cliquer sur le certificat dans la section Certificats puis sur Approuver
- Cocher `Utiliser ce certificat comme racine approuvée` et `Documents certifiés`
Puis ensuite lorsque nous ouvrons le fichier `signed.pdf` et cliquons sur la signature :

![/images/Pasted image 20260417000356.png](/images/Pasted%20image%2020260417000356.png)

Ouvrons le Panneau signature :
![/images/Pasted image 20260417000331.png](/images/Pasted%20image%2020260417000331.png)

> Le Root CA de DigiCert étant déjà dans le Trust Store d'Adobe, nous n'avons pas à l'importer manuellement.

Le LAB est validé ✅.

____

## Conclusion

Dans ce Lab j'ai contruit une infrastructure PKI et implémenter la signature PDF **PAdES-LTV**. De ça j'ai pu apprendre :
- ce qu'est un **HSM** et comment interagir avec via **PKCS#11**
- la signature PDF avec **PyHanko**
- pourquoi **PAdES-LTV** est important pour la signature de diplôme

Le lab présente cependant quelques limites :
- Le PIN du token étant la seule couche de sécurité protégeant l'utilisation de la clé privée dans le HSM est écrit en clair dans le code source du script de signature
- L'utilisation d'un émulateur logiciel de HSM 
