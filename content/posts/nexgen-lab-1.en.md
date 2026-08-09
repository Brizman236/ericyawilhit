---
title: "Federating Enterprise Identity: Deploying a Sovereign SSO Architecture with FreeIPA and Keycloak" 
date: 2026-05-28 
draft: false 
description: "Faced with the risks of scattered identities and dormant accounts, this technical guide walks through building a robust IAM infrastructure. Through a hands-on lab interconnecting FreeIPA (LDAP/Kerberos) and Keycloak, discover how to centralize authentication and implement an SSO mechanism via OpenID Connect (OIDC) to secure critical applications like Gitea and Grafana." 
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
  alt: Digital signature of diplomas 
  relative: false

---

## Context & Objectives

NexGen Solution is a modern, fast-growing company facing a number of critical problems:

- Weak password management
- Scattered identities
- Dormant accounts that still have access

These issues put the company in a delicate position that can lead to serious consequences. For example, if an employee resigns to join a competitor but their access remains active, this can result in a data leak, damaging NexGen's reputation.

What NexGen needs is a centralized identity and access management infrastructure. Technically, this means putting in place:

- A single source of truth for users via a centralized directory: this allows for instant revocation of access
- An SSO (**Single Sign-On**) mechanism for its web applications, which reduces credential sprawl by allowing a single authentication and improves productivity by sparing employees from having to remember 10 different passwords for 10 different services
- Access control policies

This lab is part of a personal learning process aimed at developing my skills in identity security by mastering:

- **Mastery of the chain of trust:**
    - Understanding how a certificate (PKI) becomes the proof element used to secure an identity (LDAPS/StartTLS), and how trust is passed on from the identity server to the application.
- **Anatomy of federation protocols:**
    - Beyond SAML, breaking down how **token exchanges** work. Understanding the difference between a flow where the server talks directly to the client and one where the user acts as an intermediary (back-channel vs. front-channel).
- **Understanding authentication delegation (Kerberos):**
    - Mastering the concept of the "Ticket-Granting Ticket" (TGT). Knowing how a user can prove their identity to the network once, without ever sending their password over the wire again.
- **Interoperability and standardization:**
    - Learning how to make heterogeneous systems talk to each other (a Linux container, a Rocky VM, a web application) using open standards to avoid proprietary lock-in.
- **Hybridizing infrastructures:**
    - Understanding the network mechanisms (DNS, routing, ports) that allow an identity to cross virtualization layers (VM ↔ container).

---

### Network Configuration

|**Machine / Service**|**FQDN**|**Role / Description**|**Critical Ports**|
|:-:|:-:|:-:|:-:|
|**FreeIPA Server**|`ipa.nexgen.lab`|Source of truth (LDAP, Kerberos, DNS, PKI)|`389`, `636`, `88`, `464`, `53`|
|**Fedora Workstation**|`fedora.nexgen.lab`|Client workstation joined to the domain (HBAC/SUDO testing)|Outbound flows|
|**Linux Server 1**|`server-1.nexgen.lab`|Infrastructure server (restricted SysAdmin access)|`22 (sshd)`|
|**Keycloak (IdP)**|`sso.nexgen.lab`|Identity Federation & SSO gateway (OIDC)|`80`, `443`|
|**Gitea (SP)**|`git.nexgen.lab`|Software forge (OpenID Connect client)|`80` or `443`|
|**Grafana (SP)**|`grafana.nexgen.lab`|Monitoring & metrics (OpenID Connect client)|`80` or `443`|

---

### Step 1: The Core of Identity (FreeIPA)

The company needs to centralize its identities in order to:

- **Reduce human error and workload** by automating the creation of user and service accounts
- **Minimize security risk** by preventing dormant accounts through instant access revocation

To do this, the solution we'll use is **FreeIPA**, an open-source identity, policy, and audit (**IPA**) management system designed for Linux environments. The choice of **FreeIPA** can be justified by these characteristics:

- It **natively integrates** an **LDAP** server (for storage), a **Kerberos** server for secure authentication, a **DNS** server, and a **PKI** used to encrypt traffic. For NexGen, this avoids the need to stand up 4 different servers
- It is **open-source**, unlike black-box solutions such as **Microsoft Active Directory**, letting us see exactly how LDAP and Kerberos work together — perfect for mastering these flows

---

#### Step 1.1: Configuring the VM's Identity

```sh
# 1. Cleanly rename the machine at the system level
sudo hostnamectl set-hostname ipa.nexgen.lab

# 2. Add it to /etc/hosts for immediate local resolution
echo "192.168.101.10 ipa.nexgen.lab ipa" | sudo tee -a /etc/hosts

# 3. Open the ports through the firewall
firewall-cmd --add-service=freeipa-ldap --add-service=freeipa-ldaps
firewall-cmd --add-service=freeipa-ldap --add-service=freeipa-ldaps --permanent

sudo firewall-cmd --permanent --add-port={80/tcp,443/tcp,389/tcp,636/tcp,88/tcp,464/tcp,53/tcp,88/udp,464/udp,53/udp,123/udp}
sudo firewall-cmd --reload
```

#### Step 1.2: Installing and Configuring the FreeIPA Server

```sh
# 1. Install the required packages
dnf install freeipa-server freeipa-server-dns

# 2. Install the server
# DM Password: w55MZaLqQBxY6TlyuZRd7g==
# Admin Password: hniqhVIQSyMTMetpiESJPg==
ipa-server-install --setup-dns -r NEXGEN.LAB -n nexgen.lab -p w55MZaLqQBxY6TlyuZRd7g== -a hniqhVIQSyMTMetpiESJPg== --mkhomedir --hostname ipa.nexgen.lab  -N -U --forwarder=1.1.1.1  --ip-address=192.168.101.10

# 3. Verify that all services are running
ipactl status
```

![Pasted image 20260515224648](/images/Pasted%20image%2020260515224648.png)

---

### Step 2: System Enrollment

The company needs to join its workstations and servers to a single source of authentication in order to:

- Simplify equipment management by eliminating the need to create local accounts machine by machine
- Guarantee their security by enabling centralized management of `sudo` rights and Host-Based Access Control (deciding which user is allowed to connect to which machine)

We're going to configure and join a Fedora client machine to the domain:

```sh
# 1. Change the FQDN of the client
sudo hostnamectl set-hostname fedora.nexgen.lab
# 2. Add it to /etc/hosts for immediate local resolution
echo "192.168.101.2 fedora.nexgen.lab" | sudo tee -a /etc/hosts

# 2. Assign a static IP with DNS pointing to the FreeIPA server
sudo nmcli c mod 'Wired connection 2' ipv4.address 192.168.101.2/24 ipv4.gateway 192.168.101.1 ipv4.dns 192.168.101.10 ipv4.method auto
sudo nmcli c down 'Wired connection 2' && sudo nmcli c up 'Wired connection 2'

# 3. Install the FreeIPA client
sudo dnf install freeipa-client -y

# 4. Join the client to the domain
ipa-client-install --domain=nexgen.lab --server=ipa.nexgen.lab --realm=NEXGEN.LAB --mkhomedir --hostname fedora.nexgen.lab -N -U --ip-address=192.168.101.2 -w hniqhVIQSyMTMetpiESJPg== -p admin

# 5. Add a user from the FreeIPA server to verify
echo 'Y8DWBGdrvSxi+dahy+REiQ==' | ipa user-add 'e.anderson' --first='Elliot' --last='Anderson' --cn='Elliot Anderson' --displayname='elliot' --initials='EA' --shell='/bin/bash' --email='e.anderson@nexgen.lab' --password --city='Dakar' --state='Sénégal'

# 6. Log in from the fedora client
su - e.anderson
```

The last command will prompt for the predefined password and then a new password.

---

### Step 3: Privilege and Access Management

The company needs to segment access and privileges across its machines in order to:

- **Limit the attack surface of its fleet** by strictly defining which users can connect where (HBAC – _Host-Based Access Control_), thereby preventing unauthorized access to critical machines.
- **Guarantee the principle of least privilege** by ensuring that staff only have the rights strictly necessary to carry out their duties, in particular through fine-grained, centralized management of administrative (`sudo`) rights.

#### Step 3.1: Creating Identities and Groups

To bring this requirement to life in the lab, we're going to create two user groups and two test users.

> I added another machine to the domain, `server-1.nexgen.lab`.

**Creating the groups**

```sh
# Create the System Administrators group
ipa group-add grp-sysadmins --desc="NexGen fleet administrators"

# Create the Developers group
ipa group-add grp-developpers --desc="NexGen development team"
```

![Pasted image 20260516090751](/images/Pasted%20image%2020260516090751.png)

**Creating users and assigning them**

```sh
# Create and assign to the grp-sysadmins group
ipa user-add m-admin --first='Mamadou' --last='Admin' --cn 'Mamadou Admin' --random
echo 'NexGen2026!' | ipa user-mod m-admin --password
ipa group-add-member grp-sysadmins --users=m-admin

# Create and assign to the grp-developpers group
ipa user-add e-dev --first='Mamadou' --last='Dev' --random 
echo 'NexGen2026?' | ipa user-mod m-dev --password 
# Add to their group
ipa group-add-member grp-developpers --users=m-dev
```

#### Step 3.2: Multi-Machine Access Control (HBAC)

By default, **FreeIPA** has an `allow_all` rule that lets every user log in to any machine in the domain. We're going to disable it and adjust our policy to reflect the reality of a business environment:

- **Administrators** must be able to log in to **all machines** (`fedora` and `server-1`)
- **Developers** only on the `fedora` machine

```sh
# 1. Make sure allow_all is properly disabled
ipa hbacrule-disable allow_all

# 2. Create the rule for SysAdmins (access everywhere)
ipa hbacrule-add allow_sysadmin_global --desc="Allows admins across the whole fleet" 
ipa hbacrule-add-user allow_sysadmin_global --groups=grp-sysadmins 
ipa hbacrule-add-host allow_sysadmin_global --hosts={fedora.nexgen.lab,server-1.nexgen.lab}
ipa hbacrule-add-service allow_sysadmin_global --hbacsvcs=sshd --hbacsvcs=login

# 4. CREATE THE RULE FOR DEVS (Fedora access only)
ipa hbacrule-add allow_dev_restricted --desc="Allows devs on Fedora only"
ipa hbacrule-add-user allow_dev_restricted --groups=grp-developpers
ipa hbacrule-add-host allow_dev_restricted --hosts=fedora.nexgen.lab
ipa hbacrule-add-service allow_dev_restricted --hbacsvcs=sshd --hbacsvcs=login
```

#### Step 3.3: Centralized SUDO (Least Privilege)

Having decided which users or user groups can access which machine, we now need to decide what rights each user should have — which actions they're allowed to perform. To do this, we'll apply the principle of least privilege.

Traditionally, this is done by editing the `/etc/sudoers` file on each machine. With a directory in place, however, we configure the rule **once** on the **FreeIPA** server and the domain machines apply it directly.

```sh
# 1. Create the sudo rule
ipa sudorule-add rule-sysadmin-sudo --desc="Root rights for NexGen sysadmins"

# 2. Assign the beneficiary group
ipa sudorule-add-user sr-sysadmins-root --groups=grp-sysadmins

# 3. Allow executing ALL commands (all) as ALL users (all)
ipa sudorule-mod rule-sysadmin-sudo --cmdcat=all --hostcat=all --runasusercat=all --runasgroupcat=all
```

If we stop here, we'd get the following error when running a command with `sudo`:

```Plaintext
sudo: PAM account management error: Permission denied
sudo: a password is required
```

This happens because `sudo` is a `PAM` sub-service which, after we disabled the **HBAC rule** `allow_all`, we never authorized for any user or user group.

To allow the sysadmins to access this service, we need to add it to the **Services** of the `allow_sysadmin_global` **HBAC rule**:

```sh
ipa hbacrule-add-service allow_sysadmin_global --hbacsvcs=sudo
```

> **NB:** By default, users don't have permission to run `sudo`, which is why we didn't configure a rule that explicitly forbids it for the developers group.

---

### Step 4: Deploying Keycloak

In infrastructure environments, identities and access are managed using protocols like **LDAP** and **Kerberos**, with rules applied to users and domain machines. Nowadays, companies rely on internal applications such as web portals, HR tools, or web APIs. To secure them, **authentication** and **access management** mechanisms need to be put in place — but these applications aren't compatible with the traditional protocols used for these mechanisms, such as **Kerberos** and **LDAP**. They can't:

- Communicate with the **LDAP** directory, the source of truth
- Use **Kerberos** for authentication
- Interact with **FreeIPA** or **Active Directory** for access and privilege management

**So how do we solve this?** This is where **Keycloak** comes in. It's an open-source identity and access management solution designed for web applications. It includes:

- An **authentication system**
- A **password database**
- A **privilege management system** It acts as a "**translator**" between identity/access management protocols and web applications.

---

#### The Deployment

> For this deployment I followed a guide provided by [IT-Connect](https://www.it-connect.fr/tuto-keycloak-installation-avec-docker/)

##### 1. DNS and Directory Structure

```sh
# 1. Configure Keycloak's domain name (on the FreeIPA server)
ipa dnsrecord-add nexgen.lab sso --a-ip-address=192.168.101.208

# 2. Create the folder structure (on sso.nexgen.lab)
mkdir -p /opt/docker-compose/keycloak && cd /opt/docker-compose/keycloak
mkdir certs postgresql
```

The expected final result is:

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

##### 2. The Docker Compose File for Keycloak

The `docker-compose.yml` file will contain:

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

A few explanations about the contents of this file.

The first part declares the **`keycloak`** service, with a container named **`keycloak_app`**:

- Various **environment variables** are defined under **`environment`**. Some of them will later be pulled from a **`.env`** file, which makes it easier to share values across several containers (reducing the risk of errors related to value consistency).
- **`KC_HTTPS_CERTIFICATE_FILE: /etc/x509/https/tls.crt`**: the name of the file corresponding to the TLS certificate (HTTPS access).
- **`KC_HTTPS_CERTIFICATE_KEY_FILE: /etc/x509/https/tls.key`**: the name of the file corresponding to the private key associated with the certificate.
- **`./certs:/etc/x509/https`**: the **`certs`** directory at the root of the project is mapped into the container. This makes it easy to push the certificate files into the container.
- The **`ports`** section indicates that the container will be exposed on two ports: **`80`** for HTTP access (which could even be skipped) and **`443`** for HTTPS access.

The second part declares the **`keycloak_postgres`** service, with a container named **`keycloak_postgres`**:

- Two **environment variables** are defined under **`environment`**, specifying the username and password used to connect to the instance. These values will be defined in the **`.env`** file.
- **`./postgresql:/var/lib/postgresql/data`**: the **`postgresql`** directory at the root of the project is mapped into the container. This ensures the persistence of the database's data, and therefore of our application.

##### 3. Environment Variables

Next, we'll create the `.env` file that will contain the environment variables:

```
KEYCLOAK_USER=admin
KEYCLOAK_PASSWORD=P@ssword!
KEYCLOAK_URL=sso.nexgen.lab
POSTGRES_USER=postgres
POSTGRES_PASSWORD=Postgres@Nexgen
```

##### 4. Keycloak's TLS Certificate

For this lab, we're going to generate a self-signed certificate in `certs`. First, we'll create the certificate's configuration file:

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

##### 5. Launching the Deployment

We'll now launch the deployment with the `docker compose up` command in the `/opt/docker-compose/keycloak/` directory

---

### Step 5: Configuring Keycloak

The goal of this step is to make our **Identity Provider (IdP)** fully operational. We'll organize this configuration around two main axes:

- **Identity Federation (LDAP binding):** Interconnecting Keycloak with the FreeIPA directory. This will dynamically synchronize user accounts, their attributes, and password verification, avoiding any local identity management within Keycloak.
    
- **SSO Federation (Client declaration):** Registering and configuring our two target applications (Gitea and Grafana) as trusted "Clients" to bring the single sign-on mechanism to life.
    

#### Step 5.1: Identity Federation

Before hooking our applications up to Keycloak, it first needs to know about the users. We'll link it with FreeIPA:

- In the left-hand menu, go to **User Federation**, then **Ldap Provider**
- Settings:
    - **UI display name**: `FreeIPA`
    - **Vendor**: `Red Hat Directory Server`, since FreeIPA is based on Red Hat
    - **Connection URL**: `ldap://ipa.nexgen.lab:389`
    - **Bind DN**: `uid=admin,cn=users,cn=accounts,dc=nexgen,dc=lab`
    - **Bind Credentials**: `hniqhVIQSyMTMetpiESJPg==` (admin password)
    - **Edit mode**: `READ_ONLY`
    - **Users DN**: `cn=users,cn=accounts,dc=nexgen,dc=lab`
    - **UUID LDAP attribute**: `ipauniqueid`
- Click **Save**

![Pasted image 20260525090649](/images/Pasted%20image%2020260525090649.png)
The LDAP federation is now working. If we search for a FreeIPA user, `m-dev` for example, in Keycloak, we'll see them: 

![Pasted image 20260525091314](/images/Pasted%20image%2020260525091314.png) 

However, this only gives us the users and their information (first name, last name, email, etc.) and not their **group**. Without groups, we can't segregate privileges between a standard user and an administrator across our applications. To address this, we need to use **LDAP Mappers**, a feature used to pull groups from the directory and associate them with the corresponding users:

- Click **User Federation** in the left-hand menu, then the provider we just added — in my case **FreeIPA**
- On the provider's page, click the **Mapper** tab: 

![Pasted image 20260525092519](/images/Pasted%20image%2020260525092519.png)

- Click **Add Mapper**
- Fill in the form:
    - **Name**: `freeipa-groups`
    - **Mapper type**: `group-ldap-mapper`
    - **LDAP Groups DN**: `cn=groups,cn=accounts,dc=nexgen,dc=lab`
    - **Mode**: `READ_ONLY`
    - Click **Save**

After this, we can see the imported groups by clicking **Groups** in the left-hand menu:

![Pasted image 20260525101347](/images/Pasted%20image%2020260525101347.png)

Our Keycloak identity source is now ready to use.

---

### Step 5: Configuring the Clients (SPs)

A **client** is a third-party application that delegates trust to Keycloak, meaning user authentication is handled by Keycloak.

A company like NexGen may have several applications; centralizing client management in Keycloak makes it possible to:

- avoid duplicating identities by relying on a single source of truth, the **LDAP directory**
- avoid scattered credentials thanks to **SSO**, which enables single authentication across all applications (clients / SPs)
- avoid each application managing its own connections directly to the directory, which would increase the attack surface

In this step, we're going to configure two clients/applications so they can delegate trust to Keycloak. We have:

- **Gitea**: A version control system deployed in a VM at `git.nexgen.lab`
- **Grafana**: An open-source data visualization and analytics platform hosted in a VM at `grafana.nexgen.lab`

For both clients we'll use the **OpenID Connect** protocol, a standard authentication protocol that extends **OAuth 2.0**.

#### Step 5.1: Configuring Gitea

First, we'll create the client in Keycloak:

- In the menu, click **Clients**, then **Create client**
- **Client type**: `OpenID Connect`
- **Client ID**: `Gitea`
- Click **Next**
- Check **Client Authentication**: to set a password the application will use to authenticate itself when interacting with Keycloak
- Under **Authentication Flow**, check only **Standard Flow**
- Click **Next**
- **Valid redirect URLs**: `http://git.nexgen.lab/user/oauth2/Keycloak/callback`
- **Web origins**: `http://git.nexgen.lab/`
- Click **Save**
- On the client's page, go to **Credentials** and copy the secret: ![Pasted image 20260525114819](/images/Pasted%20image%2020260525114819.png)

Next, configure the use of OpenID Connect as an authentication method on Gitea:

- Log in as an administrator on **Gitea**
- Click the profile picture in the top-left corner, then **Site Administration**
- In the left-hand menu, go to **Identity Access**, then **Authentication Sources**
- Click **Add Authentication Source**
- Fill in the form: - **Authentication Type**: `OAuth2` - **Authentication Name**: `Keycloak` - **OAuth2 Provider**: `OpenID Connect` - **Client ID (Key)**: `Gitea` - **Client Secret**: the secret copied earlier - **OpenID Connect Auto Discovery URL**: `https://sso.nexgen.lab/realms/master/.well-known/openid-configuration`

If we validate the config at this point, we'll get an error saying the certificate authority that signed Keycloak's certificate isn't recognized:

![Pasted image 20260525121844](/images/Pasted%20image%2020260525121844.png)

To fix this, we need to add Keycloak's TLS certificate to the trust store of the system hosting Gitea.

```sh
# 1. From Keycloak, copy the certificate to Gitea
scp /opt/docker-compose/keycloak/certs/tls.crt root@git.nexgen.lab:~/

# 2. On git.nexgen.lab, copy the certificate into the Gitea container's /usr/local/share/ca-certificates
docker cp tls.crt gitea:/usr/local/share/ca-certificates/

# 3. Update the trust store
docker exec -u root -it gitea /bin/bash update-ca-certificates
```

Then, when we try adding the authentication source again, it succeeds.

![Pasted image 20260525175639](/images/Pasted%20image%2020260525175639.png) After logging out and going to the login page, we notice a new login option:

![Pasted image 20260525183009](/images/Pasted%20image%2020260525183009.png)

Let's test it with the domain user `m-dev`: 

![Pasted image 20260525183228](/images/Pasted%20image%2020260525183228.png)

<video width="100%" controls> <source src="/videos/test-gitea-keycloak-authentication-source.webm" type="video/webm"> Your browser does not support playing this video. </video>

Gitea can now delegate user authentication to Keycloak.

---

#### Step 5.2: Configuring Grafana

As with the previous configuration, we'll first create the client in Keycloak:

- In the menu, click **Clients**, then **Create client**
- **Client type**: `OpenID Connect`
- **Client ID**: `Grafana`
- Click **Next**
- Check **Client Authentication**
- Under **Authentication Flow**, check only **Standard Flow**
- Click **Next**
- **Valid redirect URLs**: `http://grafana.nexgen.lab/login/generic_oauth`
- **Valid post logout redirect URIs**: `http://grafana.nexgen.lab/`
- **Web origins**: `http://grafana.nexgen.lab`
- Click **Save**
- On the client's page, go to **Credentials** and copy the secret.

Next, we'll configure Wiki.js so it delegates authentication to Keycloak:

- Log in as an administrator
- In the left-hand menu, under **Administration**, click **Authentication**
- Click **Generic OAuth**
- **Display name**: `OAuth`
- **Client ID**: `Grafana`
- **Scopes**:
    - `profile`: allow Grafana to retrieve information from the user's profile (first name, last name, etc.)
    - `email`: allow Grafana to retrieve the user's email address
- **Auth URL**: `https://sso.nexgen.lab/realms/master/protocol/openid-connect/auth`
- **Token URL**: `https://sso.nexgen.lab/realms/master/protocol/openid-connect/token`
- **API URL**: `https://sso.nexgen.lab/realms/master/protocol/openid-connect/userinfo`
- Check `Allow sign up`
- **Sign out redirect URL**: `https://sso.nexgen.lab/realms/master/protocol/openid-connect/logout`
- **Save** & **Enable**

---

<video width="100%" controls> <source src="/videos/sso-validated.webm" type="video/webm"> Your browser does not support playing this video. </video>