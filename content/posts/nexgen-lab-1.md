---
title: "Fédérer l'Identité d'Entreprise : Déploiement d'une Architecture SSO Souveraine avec FreeIPA et Keycloak"
date: 2026-05-28
draft: false
description: Face aux risques d'éparpillement des identités et des comptes dormants, ce guide technique détaille la mise en place d'une infrastructure IAM robuste. À travers un laboratoire pratique interconnectant FreeIPA (LDAP/Kerberos) et Keycloak, découvrez comment centraliser l'authentification et implémenter un mécanisme SSO via OpenID Connect (OIDC) pour sécuriser des applications critiques comme Gitea et Grafana.
tags:
  - IAM
  - SSO
  - Keycloak
  - FreeIPA
  - OpenID Connect
  - LDAP
  - Kerberos
  - HBAC
  - Linux Security
  - DevSecOps
cover:
  image: /images/nexgen-1-topo.png
  alt: Signature numérique de diplômes
  relative: false
---


## Contexte & Objectifs

NexGen Solution est une entreprise moderne qui explose mais qui fait face à un certains nombres de porblèmes critiques : 
- Une faible gestion des mots de passe
- L'éparpillement des identités
- Présence des comptes dormant avec des accès

Ces problèmes la mettent dans une position délicate pouvant entraîner de graves conséquences. Par exemple un employé vient à démissionner pour la concurrence mais que ses accès demeurent, ce dernier peut causer une fuite de données, dégradant la réputation de Nex Gen.

Ce dont Nex Gen a besoin est une infrastructure de gestion centralisé des identités et des accès. Techniquement il s'agit de mettre en place :
- Une source de vérité unique pour les utilisateurs via un annuaire centralisé : cela permet une révocation instantanée des accès
- Un mécanisme de SSO (**Single Sign On**) pour ses applications Web, ce qui réduit l'éparpillement des identifiants en permettant une seule authentification et améliore la productivité en évitant aux employés de mémoriser 10 mots de passe différents pour 10 services différents
- Des politiques de contrôles d'accès

Ce lab s'inscrit dans une démarche d'apprentissage me permettant de développer mes compétences dans la sécurité de l'identité en maîtrisant :
- **Maîtrise de la chaîne de confiance :**    
    - Comprendre comment un certificat (PKI) devient l'élément de preuve pour sécuriser une identité (LDAPS/StartTLS) et comment la confiance se transmet du serveur d'identité à l'application.        
- **Anatomie des protocoles de Fédération :**    
    - Au-delà du SAML, décortiquer le fonctionnement des **échanges de jetons (Tokens)**. Comprendre la différence entre un flux où le serveur parle directement au client et celui où l'utilisateur joue le rôle d'intermédiaire (Back-channel vs Front-channel).        
- **Compréhension de la délégation d'authentification (Kerberos) :**    
    - Maîtriser le concept de "Ticket-Granting Ticket" (TGT). Savoir comment un utilisateur prouve son identité au réseau une seule fois sans jamais renvoyer son mot de passe sur le fil.        
- **Interopérabilité et Standardisation :**    
    - Apprendre à faire dialoguer des systèmes hétérogènes (un conteneur Linux, une VM Rocky, une application Web) en utilisant des standards ouverts pour éviter l'enfermement propriétaire.        
- **Hybridation des infrastructures :**    
    - Comprendre les mécanismes réseau (DNS, routage, ports) qui permettent à une identité de traverser les couches de virtualisation (VM ↔ Conteneur).

___

### Configuration réseau

| **Machine / Service**  |       **FQDN**        |               **Rôle / Description**                |       **Ports Critiques**       |
| :--------------------: | :-------------------: | :-------------------------------------------------: | :-----------------------------: |
|   **FreeIPA Server**   |   `ipa.nexgen.lab`    |     Source de vérité (LDAP, Kerberos, DNS, PKI)     | `389`, `636`, `88`, `464`, `53` |
| **Fedora Workstation** |  `fedora.nexgen.lab`  |  Poste client intégré au domaine (Test HBAC/SUDO)   |          Flux sortants          |
|   **Linux Server 1**   | `server-1.nexgen.lab` | Serveur d'infrastructure (Accès restreint SysAdmin) |           `22 (sshd)`           |
|   **Keycloak (IdP)**   |   `sso.nexgen.lab`    |  Passerelle de Fédération d'Identité & SSO (OIDC)   |           `80`, `443`           |
|     **Gitea (SP)**     |   `git.nexgen.lab`    |      Forge logicielle (Client OpenID Connect)       |          `80` ou `443`          |
|    **Grafana (SP)**    | `grafana.nexgen.lab`  |   Supervision & Métriques (Client OpenID Connect)   |          `80` ou `443`          |

___

### Étape 1 : Le Cœur de l'Identité (FreeIPA)

L'entreprise a besoin de centraliser ses identités afin de 
- **Réduire l'erreur humaine et la charge de travail** en automatisant la création des comptes utilisateurs et de services
- **Minimiser le risque de sécurité** en empêchant la présence des comptes dormants grâce à la révocation instantanée des accès.

Pour ce faire, la solution que nous allons utiliser est **FreeIPA**, un système open-source de gestion des identités, des politiques et des audits (**IPA**) conçu pour des environnements Linux. Le choix de **FreeIPA** peut être justifié par ces caractéristiques :
- Il i**ntègre nativemen**t un serveur **LDAP** (permettant le stockage), un serveur **Kerberos** pour l'authentification sécurisée, un serveur **DNS** et une **PKI** servant à chiffrer les flux. Pour NexGen cela lui évite de créer 4 serveurs différents
- il est **Open-Source**, contrairement aux solutions boîte-noire comme **Microsoft Active Directory** il nous permet de voir exactement comment LDAP et Kerberos s'articulent ensemble ce qui est parfait pour maîtriser les flux

___

#### Étape 1.1 : Configuration de l'Identité de la VM

```sh
# 1. On renomme la machine proprement au niveau du système
sudo hostnamectl set-hostname ipa.nexgen.lab

# 2. On l'ajoute dans le fichier /etc/hosts pour la résolution locale immédiate
echo "192.168.101.10 ipa.nexgen.lab ipa" | sudo tee -a /etc/hosts

# 3. Ouverture des ports à travers le Pare-Feu
firewall-cmd --add-service=freeipa-ldap --add-service=freeipa-ldaps
firewall-cmd --add-service=freeipa-ldap --add-service=freeipa-ldaps --permanent

sudo firewall-cmd --permanent --add-port={80/tcp,443/tcp,389/tcp,636/tcp,88/tcp,464/tcp,53/tcp,88/udp,464/udp,53/udp,123/udp}
sudo firewall-cmd --reload
```


#### Étape 1.2 : Installation et configuration du serveur FreeIPA

```sh
# 1. Installation des packages nécessaires
dnf install freeipa-server freeipa-server-dns

# 2. Installation du serveur
# DM Password : w55MZaLqQBxY6TlyuZRd7g==
# Admin Password : hniqhVIQSyMTMetpiESJPg==
ipa-server-install --setup-dns -r NEXGEN.LAB -n nexgen.lab -p w55MZaLqQBxY6TlyuZRd7g== -a hniqhVIQSyMTMetpiESJPg== --mkhomedir --hostname ipa.nexgen.lab  -N -U --forwarder=1.1.1.1  --ip-address=192.168.101.10

# 3. Vérifier que tous les services tournent
ipactl status
```

![Pasted image 20260515224648](/images/Pasted%20image%2020260515224648.png)

___

### Etape 2 : Enrollement Système

L'entreprise a besoin de raccorder ses postes de travail et serveurs à une source unique d'authentification afin de :
- Faciliter la gestion des équipements en supprimant les créations des comptes locaux machine par machine
- Garantir la sécurité de ces derniers en permettant la gestion centraliser des droits `sudo` et de faire du Host-Based Access Control (décider quel utilisateur à le droit de se connecter sur quelle machine)

Nous allons configurer et intégrer une machine cliente fedora dans le Domaine :

```sh
# 1. Changement du FQDN du Client
sudo hostnamectl set-hostname fedora.nexgen.lab
# 2. On l'ajoute dans le fichier /etc/hosts pour la résolution locale immédiate
echo "192.168.101.2 fedora.nexgen.lab" | sudo tee -a /etc/hosts

# 2. Attribution d'une IP Statique avec DNS pointant vers le serveur FreeIPA
sudo nmcli c mod 'Wired connection 2' ipv4.address 192.168.101.2/24 ipv4.gateway 192.168.101.1 ipv4.dns 192.168.101.10 ipv4.method auto
sudo nmcli c down 'Wired connection 2' && sudo nmcli c up 'Wired connection 2'

# 3. Installation du client FreeIPA
sudo dnf install freeipa-client -y

# 4. Jointure du client au domaine
ipa-client-install --domain=nexgen.lab --server=ipa.nexgen.lab --realm=NEXGEN.LAB --mkhomedir --hostname fedora.nexgen.lab -N -U --ip-address=192.168.101.2 -w hniqhVIQSyMTMetpiESJPg== -p admin

# 5. Ajout d'un utilisateur depuis le serveur FreeIPA pour la vérification
echo 'Y8DWBGdrvSxi+dahy+REiQ==' | ipa user-add 'e.anderson' --first='Elliot' --last='Anderson' --cn='Elliot Anderson' --displayname='elliot' --initials='EA' --shell='/bin/bash' --email='e.anderson@nexgen.lab' --password --city='Dakar' --state='Sénégal'

# 6. Connexion depuis le client fedora
su - e.anderson
```

La dernière commande nous demandera le mot de passe prédéfini et un nouveau mot de passe.

___

### Etape 3 : Gestion des Privilèges et Contrôle d'Accès

L'entreprise a besoin de sectoriser les accès et les privilèges sur ses machines afin de : 
 - **Limiter la surface d'attaque du parc informatique** en définissant de manière stricte le périmètre de connexion des utilisateurs (HBAC - _Host-Based Access Control_), empêchant ainsi un accès non autorisé aux machines critiques.     
 - **Garantir le principe de moindre privilège** en s'assurant que les collaborateurs ne disposent que des droits strictement nécessaires à l'accomplissement de leurs missions, notamment à travers une gestion fine et centralisée des droits d'administration (`sudo`).

#### Etape 3.1 : Création des Identités et des Groupes

Pour matérialiser ce besoin dans le lab, nous allons créer deux groupes d'utilsateurs et deux utilisateurs test. 

> J'ai ajouté une autre machine au domaine `server-1.nexgen.lab` .

**Création des groupes**

```sh
# Création du groupe des Administrateurs Système
ipa group-add grp-sysadmins --desc="Administrateurs du parc NexGen"

# Création du groupe des Développeurs
ipa group-add grp-developpers --desc="Équipe de développement NexGen"
```

![Pasted image 20260516090751](/images/Pasted%20image%2020260516090751.png)

**Créations des utilisateurs et assignation**

```sh
# Création et attribution du groupe grp-sysadmins
ipa user-add m-admin --first='Mamadou' --last='Admin' --cn 'Mamadou Admin' --random
echo 'NexGen2026!' | ipa user-mod m-admin --password
ipa group-add-member grp-sysadmins --users=m-admin

# Création et attribution du groupe grp-developpers
ipa user-add e-dev --first='Mamadou' --last='Dev' --random 
echo 'NexGen2026?' | ipa user-mod m-dev --password 
# Ajout dans son groupe 
ipa group-add-member grp-developpers --users=m-dev
```

#### Etape 3.2 : Le Contrôle d'Accès (HBAC) Multi-machine

Par défaut, **FreeIPA** dispose d'un règle `allow_all` qui autorise tous les utilisateurs à se connecter sur n'importe quelle machine du domaine. Nous allons la désactiver et modifier notre stratégie pour refléter la réalité en entreprise :
- Les **administrateurs** doivent pourvoir se connecter à **toutes les machines** (`fedora` et `server-1`)
- Les **Développeurs** que sur la machine `fedora`

```sh
# 1. S'assurer que allow_all est bien désactivé 
ipa hbacrule-disable allow_all

# 2. Création des règles pour les SysAdmin (accès partout)
ipa hbacrule-add allow_sysadmin_global --desc="Autorise les admins sur tout le parc" 
ipa hbacrule-add-user allow_sysadmin_global --groups=grp-sysadmins 
ipa hbacrule-add-host allow_sysadmin_global --hosts={fedora.nexgen.lab,server-1.nexgen.lab}
ipa hbacrule-add-service allow_sysadmin_global --hbacsvcs=sshd --hbacsvcs=login

# 4. CRÉATION DE LA RÈGLE POUR LES DEVS (Accès Fedora uniquement)
ipa hbacrule-add allow_dev_restricted --desc="Autorise les devs uniquement sur la Fedora"
ipa hbacrule-add-user allow_dev_restricted --groups=grp-developpers
ipa hbacrule-add-host allow_dev_restricted --hosts=fedora.nexgen.lab
ipa hbacrule-add-service allow_dev_restricted --hbacsvcs=sshd --hbacsvcs=login
```


#### Etape 3.3 : Le SUDO Centralisé (Moindre Privilège)

Après avoir décidé quels utilisateurs ou groupe d'utilisateurs peuvent accéder à telle ou telle machine, il nous faut maintenant décidé quel droit chaque utilisateur doit avoir, quelles actions sont elles permises. Pour ce faire nous allons appliquer le principe du moindre privilège.

Traditionnellement cela se fait en éditant le fichier `/etc/sudoers` sur chaque machine, cependant avec un Annuaire, on  configurera **seule fois** la règle sur le server **FreeIPA** et les machines du domaine vont l'appliquer directement.

```sh
# 1. Créer la règle Sudo
ipa sudorule-add rule-sysadmin-sudo --desc="Droits root pour les sysadmins de NexGen"

# 2. Assigner le groupe bénéficiaire
ipa sudorule-add-user sr-sysadmins-root --groups=grp-sysadmins

# 3. Autoriser l'exécution de TOUTES les commandes (all) en tant que TOUS les utilisateurs (all)
ipa sudorule-mod rule-sysadmin-sudo --cmdcat=all --hostcat=all --runasusercat=all --runasgroupcat=all
```

Si l'on s'arrête là, on obtiendrai l'erreur ci-dessous lors de l'execution d'une commande avec `sudo` :

```Plaintext
sudo: PAM account management error: Permission denied
sudo: a password is required
```

Cela se produit car `sudo` est un sous-service `PAM`, un sous-service qu'après avoir désactivé le **HBAC Rule** `allow_all` nous n'avons pas autorisé pour un quelconque utilisateur ou groupe d'utilisateur.

Pour pouvoir permettre aux Sysadmins d'accéder à ce service, nous allons l'ajouter aux **Services** du **HBAC Rule** `allow_sysadmin_global` :

```sh
ipa hbacrule-add-service allow_sysadmin_global --hbacsvcs=sudo
```



> **NB :** Par défaut les utilisateurs n'ont pas le droit d'exécuter `sudo` c'est pourquoi nous n'avons pas configurer une règle qui l'interdit pour le groupe des développeurs.


___

### Etape 4 : Déploiement de KeyCloak

Dans les infrastructures, les identités et les accès sont gérés grâce aux protocoles comme le **LDAP** et le **Kerberos**, des règles sont appliqués à des utilisateurs, à des machines du domaine. Les entreprises disposent de nos jours des applications internes comme un portail web, un outil RH ou bien une API web. Pour pouvoir les sécuriser, des mécanismes d'**authentification** et de **gestion des accès** doivent être mis en place; ces applications ne sont pas compatibles avec les protocoles traditionnels utilisés pour ces mécanismes comme le **Kerberos** et le **LDAP**. Elles ne peuvent pas :
- Communiquer avec l'annuaire **LDAP**, la source de vérité
- Utiliser **Kerberos** pour les authentifications
- Intéragir avec **FreeIPA** ou **Active Directory** pour la gestion des accès et des privilèges

**Comment faire ?**
C'est ici que **Keycloak** intervient. C'est une solution open-source de gestions des identités et accès conçu pour les applications web. Il intègre :
- Un **système d'authentification**
- Une **base de données de mots de passe**
- Un **système de gestion de privilège**
Il sert de "**traducteur**" entre les protocoles de gestions de l'identité et des accès et les applications web. 

___

#### Le Déploiement

> Pour ce déploiement j'ai utilisé un guide fournie par [IT-Connect](https://www.it-connect.fr/tuto-keycloak-installation-avec-docker/)

##### 1.  DNS et Arborescence des repertoires

```sh
# 1. Configuration du nom de domaine de Keycloak (Sur le serveur FreeIPA)
ipa dnsrecord-add nexgen.lab sso --a-ip-address=192.168.101.208

# 2. Création de la structure de dossier (sur sso.nexgen.lab)
mkdir -p /opt/docker-compose/keycloak && cd /opt/docker-compose/keycloak
mkdir certs postgresql
```

Le résultat finanl attendue est :
```
keycloak/
├── certs
│   ├── tls.crt
│   └── tls.key
|   └── tls.cnf
├── docker-compose.yml
├── .env
└── postgresql
```

##### 2. Le fichier Docker Compose pour Keycloak
Le fichier `docker-compose.yml` contiendra :

```yml
services:
  keycloak:
    container_name: keycloak_app
    image: quay.io/keycloak/keycloak:latest
    restart: always
    environment:
      KEYCLOAK_ADMIN: ${KEYCLOAK_USER}
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_PASSWORD}
      KC_HOSTNAME: ${KEYCLOAK_URL}
      KC_DB: postgres
      KC_DB_USERNAME: ${POSTGRES_USER}
      KC_DB_PASSWORD: ${POSTGRES_PASSWORD}
      KC_DB_URL_HOST: keycloak_postgres
      KC_DB_URL_DATABASE: keycloak
      KC_HTTPS_CERTIFICATE_FILE: /etc/x509/https/tls.crt
      KC_HTTPS_CERTIFICATE_KEY_FILE: /etc/x509/https/tls.key
    volumes:
      - ./certs:/etc/x509/https
    depends_on:
      keycloak_postgres:
        condition: service_healthy
    ports:
      - "80:8080"
      - "443:8443"
    networks:
      - keycloak-network
    command:
      - start

  keycloak_postgres:
    container_name: keycloak_postgres
    image: postgres:17
    restart: always
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - ./postgresql:/var/lib/postgresql/data
    networks:
      - keycloak-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d keycloak"]
      interval: 10s
      timeout: 5s
      retries: 5

networks:
  keycloak-network:
    name: keycloak-network
    driver: bridge
```

Quelques explications au sujet du contenu de ce fichier.

La première partie déclare le service **`keycloak`**, avec un conteneur qui sera nommé **`keycloak_app`** :

- Différentes **variables d'environnement** sont définies sous **`environment`**. Certaines d'elles seront par la suite dans un fichier **`.env`**, ce qui facilite le partage de valeurs entre plusieurs conteneurs (ce qui limite les risques d'erreurs liées à la cohérence des valeurs).
- **`KC_HTTPS_CERTIFICATE_FILE: /etc/x509/https/tls.crt`** : nom du fichier correspondant au certificat TLS (accès HTTPS).
- **`KC_HTTPS_CERTIFICATE_KEY_FILE: /etc/x509/https/tls.key`** : nom du fichier correspondant à la clé privée associée au certificat.
- **`./certs:/etc/x509/https`** : le répertoire **`certs`** situé à la racine du projet sera mappé dans le conteneur. Ceci permet de pousser les fichiers du certificat dans le conteneur facilement.
- La section **`ports`** indique que le conteneur sera exposé sur deux ports : **`80`** pour l'accès HTTP (on pourrait même s'en passer) et **`443`** pour l'accès HTTPS.

La deuxième partie déclare le service **`keycloak_postgres`**, avec un conteneur qui sera nommé **`keycloak_postgres`** :
- Deux **variables d'environnement** sont définies sous **`environment`**, pour préciser le nom d'utilisateur et le mot de passe de connexion à l'instance. Ces valeurs seront définies dans le fichier **`.env`**.
- **`./postgresql:/var/lib/postgresql/data`** : le répertoire **`postgresql`** situé à la racine du projet sera mappé dans le conteneur. Il assure la persistance des données liées à la base de données, et donc, notre application.

##### 3. Les variables d'environnement
Nous allons par la suite créer le fichier `.env` qui contiendra les variables d'environnement :

```
KEYCLOAK_USER=admin
KEYCLOAK_PASSWORD=P@ssword!
KEYCLOAK_URL=sso.nexgen.lab
POSTGRES_USER=postgres
POSTGRES_PASSWORD=Postgres@Nexgen
```

##### 4. Le certificat TLS de KeyCloak

Dans le cadre de ce lab nous allons générer un certificat auto-signé dans `certs`. Tout d'abord nous allons créer le fichier de configuration du certificat :

```
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
x509_extensions    = v3_req
distinguished_name = dn

[ dn ]
C  = SN
ST = Dakar
O  = NexGen Lab
OU = Security
CN = sso.nexgen.lab

[ v3_req ]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ alt_names ]
DNS.1 = sso.nexgen.lab
```

```sh
sudo openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout tls.key -out tls.crt --config tls.cnf -extensions v3_req
```

##### 5. Lancer le déploiement

Nous allons lancer le déploiement dès à présent avec la commande `docker compose up` dans le répertoire `/opt/docker-compose/keycloak/`


___

### Etape 5 : Configuration de Keycloak

L'objectif de cette étape est de rendre notre **Fournisseur d'Identité (IdP)** pleinement opérationnel. Nous allons structurer cette configuration autour de deux axes majeurs :

- **La Fédération d'Identité (Liaison LDAP) :** Interconnecter Keycloak avec l'annuaire FreeIPA. Cela permettra de synchroniser dynamiquement les comptes utilisateurs, leurs attributs et la vérification des mots de passe, évitant ainsi toute gestion locale des identités dans Keycloak.
    
- **La Fédération SSO (Déclaration des Clients) :** Enregistrer et configurer nos deux applications cibles (Gitea et Grafana) en tant que "Clients" de confiance afin de matérialiser le mécanisme de session unique.

#### Etape 5.1 : Fédération d'Identité

Avant de brancher nos applications à KeyCloak, ce dernier doit d'abord connaître les utilisateurs. On va le lier avec FreeIPA :
- Dans le menu gauche, aller sur **User Federation** puis **Ldap Provider**
- Les paramètres
	- **UI display name** : `FreeIPA`
	- **Vendor** : `Red Hat Directory Server` car FreeIPA est basé sur Red Hat
	-  **Connection URL**: `ldap://ipa.nexgen.lab:389`
	-  **Bind DN** : `uid=admin,cn=users,cn=accounts,dc=nexgen,dc=lab`
	- **Bind Credentials** : `hniqhVIQSyMTMetpiESJPg==` (Mot de passe admin)
	- **Edit mode** : `READ_ONLY`
	- **Users DN** : `cn=users,cn=accounts,dc=nexgen,dc=lab`
	- **UUID LDAP attribute** : `ipauniqueid`
- Cliquer sur **Save**

![Pasted image 20260525090649](/images/Pasted%20image%2020260525090649.png)

La fédération LDAP est maintenant fonctionnelle. Si l'on cherche un utilsateur FreeIPA, `m-dev` par exemple dans Keycloak, nous le verrons :
![Pasted image 20260525091314](/images/Pasted%20image%2020260525091314.png)
Cependant, ce dernier ne nous fournit que les utilisateurs et leurs informations (nom, prénom, email, ...) et non leur **groupe**. L'absence des groupes nous empêche d'effectuer la ségrégation des privilèges entre un utilisateur standard et un administrateur sur les Applications. Pour pallier cela, il nous faut utiliser les **Mappers LDAP**, fonctionnalité servant à récupérer les groupes depuis l'annuaire et les associer avec les utilisateurs correspondants :
- Cliquer sur **User Federation**  dans le menu gauche, puis sur le provider dernièrement ajouté, dans mon cas **FreeIPA**
- Sur la page du Provider, cliquer sur l'onglet **Mapper** :
	![Pasted image 20260525092519](/images/Pasted%20image%2020260525092519.png)
- Cliquer sur **Add Mapper**
- Remplir le formulaire :
	- **Name** : `freeipa-groups`
	- **Mapper type** : `group-ldap-mapper`
	- **LDAP Groups DN** : `cn=groups,cn=accounts,dc=nexgen,dc=lab`
	- **Mode** : `READ_ONLY`
	- Cliquer sur **Save**

Après cela, nous pouvons voir les groupes importés en cliquant sur **Groups** dans le menu à gauche :

![Pasted image 20260525101347](/images/Pasted%20image%2020260525101347.png)

Notre Source d'Identité Keycloak est maintenant prêt à l'emploi.

___

### Etape 5 : Configuration des clients (SP)

Un **client** est une application tierce qui délègue sa confiance à KeyCloak, c'est-à-dire que l'authentification des utilisateurs est gérée par KeyCloak. 

Une entreprise comme NexGen peut disposer de plusieurs applications, la centralisation de la gestion des clients sur KeyCloak permet :
- d'éviter la duplication des identités en utilisant une seule source de vérité, l'**annuaire LDAP**
- d'éviter l'éparpillement des identifiants grâce au **SSO** qui permet une authentification unique pour toutes les applications (clients / SPs)
- d'éviter que chaque application gère ses propres connexions directement vers l'annuaire augmentant la surface d'attaque

Dans cette étape nous allons configurer deux clients/applications afin qu'ils puissent déléguer leur confiance à KeyCloak. Nous avons :
- **Gitea** : Un système de contrôle de version déployé dans une VM au domaine `git.nexgen.lab`
- **Grafana** : Une plateforme open source de visualisation et d'analyse de données hébergée dans une VM au domaine `grafana.nexgen.lab`

Pour les deux clients nous allons utiliser le protocole **OpenID Connect**. C'est un protocole standard d'authentification, extension de l'**OAuth 2.0**. 

#### Etape 5.1 : Configuration de Gitea

Tout d'abord nous allons créer le client sur KeyCloak :
- Dans le menu, cliquer sur **Clients** puis sur **Create client**
- **Client type** : `OpenID Connect`
- **Client ID** : `Gitea`
- Cliquer sur **Next**
- Cocher **Client Authentication** : pour définir un mot de passe avec lequel l'application s'authentifiera pour intéragir avec KeyCloak
- Dans  **Authentication Flow**, cocher seulement **Standard Flow**
- Cliquer sur **Next**
- **Valid redirect URLs** : `http://git.nexgen.lab/user/oauth2/Keycloak/callback`
- **Web origins** : `http://git.nexgen.lab/`
- Cliquer sur **Save**
- Sur la page du Client, aller dans **Creadentials** puis copier le secret :
	![Pasted image 20260525114819](/images/Pasted%20image%2020260525114819.png)

Ensuite configurer l'utilisation d'OpenID Connect comment méthode d'authentification sur Gitea :
- Se connecter en tant qu'Administrateur sur **Gitea**
- Cliquer sur la photo de profil en haut à gauche, puis sur **Site Administration**
- Dans le menu à gauche, aller dans **Identity Access** puis **Authentication Sources**
- Cliquer sur **Add Authentication Source**
- Remplir le formulaire :
		- **Authentication Type** : `OAuth2`
		- **Authentication Name** : `Keycloak`
		- **OAuth2 Provider** : `OpenID Connect`
		- **Client ID (Key)** : `Gitea`
		- **Client Secret** : Le secret précédemment copié
		- **OpenID Connect Auto Discovery URL** : `https://sso.nexgen.lab/realms/master/.well-known/openid-configuration`

Si nous validons la config à ce niveau, nous aurons une erreur disant que l'autorité signataire du certificat de KeyCloak n'est pas reconnue :

![Pasted image 20260525121844](/images/Pasted%20image%2020260525121844.png)

Pour résoudre ce problème, nosu devons enregistrer le certificat TLS de Keycloak dans le trust store du système qui héberge Gitea.

```sh
# 1. Depuis Keycloak, copier le certificat vers Gitea
scp /opt/docker-compose/keycloak/certs/tls.crt root@git.nexgen.lab:~/

# 2. Sur git.nexgen.lab, copier le certificat sur le Conteneur de Gitea /usr/local/share/ca-certificates
docker cp tls.crt gitea:/usr/local/share/ca-certificates/

# 3. Mettre à jour le Trust Store
docker exec -u root -it gitea /bin/bash update-ca-certificates
```

Puis lorsque recommençons l'ajout de la source d'authentificat, il se solde par un succès.

![Pasted image 20260525175639](/images/Pasted%20image%2020260525175639.png)
En allant sur la page de connexion après s'être déconnecté, on remarque une nouvelle option de connexion : 

![Pasted image 20260525183009](/images/Pasted%20image%2020260525183009.png)

Testons-la avec l'utilisateur du domaine `m-dev` :
![Pasted image 20260525183228](/images/Pasted%20image%2020260525183228.png)

<video width="100%" controls>
  <source src="/videos/test-gitea-keycloak-authentication-source.webm" type="video/webm">
  Votre navigateur ne supporte pas la lecture de cette vidéo.
</video>

Gitea peut maintenant déléguer l'authentification de ses utilisateurs à Keycloak.

___

#### Etape 5.2 : Configuration de Grafana

Comme avec la configuration précédente, nous allons tout d'abord nous allons créer le client sur KeyCloak :
- Dans le menu, cliquer sur **Clients** puis sur **Create client**
- **Client type** : `OpenID Connect`
- **Client ID** : `Grafana`
- Cliquer sur **Next**
- Cocher **Client Authentication**
- Dans  **Authentication Flow**, cocher seulement **Standard Flow**
- Cliquer sur **Next**
- **Valid redirect URLs** : `http://grafana.nexgen.lab/login/generic_oauth`
- **Valid post logout redirect URIs** : `http://grafana.nexgen.lab/`
- **Web origins** : `http://grafana.nexgen.lab`
- Cliquer sur **Save**
- Sur la page du Client, aller dans **Creadentials** puis copier le secret.

Ensuite nous allons configurer Wiki.js afin qu'il délègue l'authentification à Keylcloak :
- Se connecter en tant qu'administrateur
- Sur le menu à gauche, sous **Administration** cliquer sur **Authentication**
- Cliquer sur **Generic OAuth**
- **Display name** : `OAuth`
- **Client ID** : `Grafana`
- **Scopes** :
	- `profile` : autoriser Grafana à récupérer des informations sur profil de l'utilisateur  (Nom, Prénom, etc)
	- `email` : autoriser Grafana à récupérer l'adresse mail de l'utilisateur
- **Auth URL** : `https://sso.nexgen.lab/realms/master/protocol/openid-connect/auth`
- **Token URL** : `https://sso.nexgen.lab/realms/master/protocol/openid-connect/token`
- **API URL** :  `https://sso.nexgen.lab/realms/master/protocol/openid-connect/userinfo`
- Cocher `Allow sign up`
- **Sign out redirect URL** : `https://sso.nexgen.lab/realms/master/protocol/openid-connect/logout`
- **Save** & **Enable**

____


<video width="100%" controls>
  <source src="/videos/sso-validated.webm" type="video/webm">
  Votre navigateur ne supporte pas la lecture de cette vidéo.
</video>