---
title: "Sécuriser le Partage de Fichiers : Implémentation du RBAC et du Provisioning JIT avec Keycloak et Nextcloud"
date: 2026-06-05
draft: false
description: "Découvrez comment implémenter une gestion des accès basée sur les rôles (RBAC) étanche et automatisée. Ce guide pratique détaille l'interconnexion entre Keycloak et Nextcloud via l'application Social Login, la transmission de la claim 'groups', et le provisioning Just-In-Time (JIT) pour cloisonner dynamiquement les dossiers d'équipe."
summary: "Guide pratique sur la mise en place du RBAC et du Provisioning Just-In-Time (JIT) entre Keycloak et Nextcloud pour sécuriser les données d'entreprise."
categories:
  - Cybersécurité
  - Infrastructure
tags:
  - IAM
  - RBAC
  - Keycloak
  - Nextcloud
  - Social Login
  - Just-In-Time Provisioning
  - OpenID Connect
cover:
  image: "/images/nexgen-2-topo.png"
  alt: "Interface Nextcloud montrant les dossiers d'équipe cloisonnés par groupe"
  relative: false
---


## Contexte & Objectif 

### Situation actuelle

Dans le **Lab 1** nous avons posé les bases de notre infrastructure avec l'implémentation de l'authentification unique pour nos applications (Gitea et Grafana). Cependant un nouvel enjeu apparaît avec l'arrivée des applications collaboratives.

### Le problème métier

La direction de NexGen déploie **Nextcloud** pour le partage de fichiers. Cependant, laisser tous les employés accéder à l'ensemble des documents viole le principe du moindre privilège, un développeur ne doit pas avoir accès à la grille de salaires de tous les employés de l'entreprise.
Les données des Ressources Humaines ne doivent pas être visibles par les équipes techniques, et vice-versa.

### Objectif du Lab 2

Faire évoluer l'infrastructure existante pour implémenter une gestion des accès basée sur les rôles (**RBAC**). L'accès aux dossiers Nextcloud doit être automatiquement restreint et provisionné à la volée en fonction du département de l'utilisateur, sans gestion locale des permissions.
Pour ce faire, nous allons créer deux groupes d'utilisateurs, **RH** et **Devs**.

___

## Etape 1 : Évolution de l'annuaire

Dans cette étape nous allons enrichir la source de vérité mise en place précédement en créant :
- les groupes `dev-empl` et `hr-empl`
- les utilisateurs `bob` et `alice` qui seront assignés à leur groupe respectif

```sh
# Création des groupes
ipa group-add dev-empl --desc="Département des développeurs"
ipa group-add hr-empl --desc="Département des Ressources Humaines"

# Création des utilisateurs
ipa user-add alice --first='Alice' --last='Dupont' --email='alice@nexgen.lab' --city "Dakar" --state='Sénégal' --orgunit='RH' --title='Responsable RH'
echo 'Azerty123' | ipa user-mod alice --password

ipa user-add bob --first='Bob' --last='Jackson' --email='bob@nexgen.lab' --city "Dakar" --state='Sénégal' --orgunit='Devs' --title='Développeur Web Senior'
echo 'Azerty123' | ipa user-mod alice --password

# Ajout des utilisateurs à leur groupe
ipa group-add-member hr-empl --users=alice
ipa group-add-member dev-empl --users=bob
```

Les groupes créés, les utilisateurs assignés à ces derniers, passons maintenant à l'étape 2
___

## Étape 2 : Extraction et Transmission des Rôles

Pour que NextCloud puisse appliquer le **RBAC**, il lui faut tout d'abord connaître le rôle, le groupe auquel l'utilisateur appartient. Cependant ce dernier ne dispose pas d'une base de données des utilisateurs du domaine. **Qui fournira les utilisateurs ? Les identités**. 
**Keycloak**. Grâce à OpenID Connect, NextCloud va **déléguer** l'authentification des utilisateurs à Keycloak, ce dernier lui renverra les informations de l'utilisateur via un jeton **JWT**. Cependant, par défaut, le jeton ne contient pas le ou les groupes du domaine de l'utilisateur.

Dans cette étape, nous allons insérer cette information en :
- Créant un **Client Scope** dédié : le **Client Scope** est un mécanisme de sécurité qui défini quelles catégories d'informations un client/SP a le droit de demander à KeyCloak. Ce Client Scope que nous allons créer à pour but de permettre à NextCloud de demander les groupes auquels appartiennent l'utilisateur.
- Configurant un **Mapper** pour ce **Client Scope** : Le Mapper aura pour rôle de définir quels informations vont être fournies, dans notre cas les groupes de l'utilisateur.

### Etape 2.1 : Création du Client Scope

- Dans le menu à gauche, cliquer sur **Client Scopes**
- Sur la page, cliquer sur **Create a client scope**
- Remplir le formulaire :
	- **Name** : `user-group`
	- **Description** : `Scope NexGen pour transmettre les groupes FreeIPA aux applications clientes`
	- **Type** : `Default`
	- **Protocol** : `OpenID Connect`
	- Cocher **Include in Token Scope**
	- Cliquer sur **Save**

	![Pasted image 20260603221010](/images/Pasted%20image%2020260603221010.png)
	
### Etape 2.2 : Configuration du Mapper
- Sur la page du Client Scope créé, cliquer sur l'onglet **Mappers**
- Cliquer sur **Configure a new mapper**
- Dans la liste, sélectionner **Group Membership**
- Configurer les paramètres ainsi :
	- Name : **group-mapper**
	- Token Claim Name : **groups**, c'est le nom exact de la clé Json qui sera dans le **JWT**
	- Décocher **Full group path** afin que Keycloak n'envoie que le nom du groupe (ex : `hr-empl`) et nom le chemin complet (`\hr-empl`)
	- Cliquer sur **Save**
	![Pasted image 20260603222051](/images/Pasted%20image%2020260603222051.png)

___
## Etape 3 : Création et Intégration du client/SP NextCloud

Dans cette étape nous allons configurer NextCloud afin qu'il puisse permettre l'authentification par OIDC. 

> Nativement, NextCloud ne dispose pas de fonctionnalité le lui permettant, c'est pourquoi l'application `Social Login` doit être installé.

#### Etape 3.1 : Création du client 

- Dans le menu à gauche, **cliquer** sur **Clients**
- Sur la page des clients, **cliquer** sur le bouton **Create client**
- Remplir les paramètres :
	- **General Settings**
		- **Client type** : `OpenID Connect`
		- **Client ID** : `nextcloud`
		- **Name** : `NextCloud`
		- Cliquer sur **Next**
	- **Capability config**
		- Cocher **Client authentication**
		- Ne cocher que **Standard Flow** dans la section **Authorization flow**
		- Cliquer sur **Next**
	- **Login settings**
		- **Root URL** : `https://nextcloud.nexgen.lab/`
		- **Valid redirect URIs** : `https://nextcloud.nexgen.lab/*`
		- **Valid post logout redirect URIs** : `https://nextcloud.nexgen.lab/`
		- **Web origins** : `https://nextcloud.nexgen.lab/`
		- Cliquer sur **Save**

Après la création du client, nous devrions copiez son secret.

### Etape 3.2 : Intégration du Client NextCloud

Dans cette étape nous allons intégrer l'authentification OIDC à NextCloud et le configurer de telle sorte qu'il utilise **Keycloak** comme **Identity Provider**.

> NB : Il faut être connecter en tant qu'admin

- **Cliquer** sur le profil puis sur **Administration settings**
- Dans le menu de gauche, à la section **Administration**, **cliquer** sur **Social login**
	- S'assurer que seulement les options ci-dessous sont cochées :
		- **Prevent creating an account if the email address exists in another account** : Empêche les duplicatas de comptes en évitant la création d'un compte si un autre user à la même adresse email
		- **Update user profile every login** : Permettre la mise à jour du profil à chaque connexion. Cela favorisera la révocation centralisée, lorsque l'on révoque un accès ou que l'on retire un rôle, NextCloud synchronise les informations quand l'utilisateur se reconnecte.
		- **Automatically create groups if they do not exist** : favorise la centralisation, car si un utilisateur est ajouté à un tout nouveau groupe, et qu'il se connecte à l'application, le groupe y est automatiquement créer.
	- **Cliquer** sur **Custom OpenID Connect**
		- **Internal name** : `keycloak`
		- **Title** : `KeyCloak`
		- **Authorize url** : `https://sso.nexgen.lab/realms/master/protocol/openid-connect/auth`
		- **Token url** : `https://sso.nexgen.lab/realms/master/protocol/openid-connect/token`
		- **User info url** : `https://sso.nexgen.lab/realms/master/protocol/openid-connect/userinfo`
		- **Logout url** : `https://sso.nexgen.lab/realms/master/protocol/openid-connect/logout`
		- **Client Id** : `nextcloud`
		- **Client Secret** : Le secret copié
		- **Scope** : `openid`
		- **Groups claim** : `groups`
		- **Button style** : `KeyCloak`
		- **Default group** : `None`
		- Cliquer sur **Save**

### Etape 3.3 : Connexion des utilisateurs sur NextCloud

Suite à la configuration du SSO sur NextCloud, nous allons connecter nos deux utilisateurs `alice` et `bob`.

<video width="100%" controls>
  <source src="/videos/sso-nextcloud.webm" type="video/webm">
  Votre navigateur ne supporte pas la lecture de cette vidéo.
</video>

Si nous nous connectons en tant qu'Administrateur et allons dans **Accounts**, nous allons remarquer que les groupes des utilisateurs ont été **automatiquement** créé dans NextCloud avec le préfix `keycloak`:

![Pasted image 20260605232824](/images/Pasted%20image%2020260605232824.png)

Les utilisateurs connectés et les groupes créés,  nous pouvons passés maintenant à la création des dossiers partagés avec des droits d'accès.

____

## Etape 4 : Création des dossiers d'équipe (Team Folder)

Dans cette étape nous allons créer deux **Team Folder**, un pour l'équipe **RH** et l'autre pouré l'équipe **Devs** puis vérifier si les droits d'accès fonctionnent réellement.

> NB : L'application **Team Folder** doit être installée

### Etape 4.1 : Création du dossier des RHs

- Se connecter en tant qu'admin, puis aller dans **Administration settings**
- Dans le menu de gauche, cliquer sur **Team Folder**
- Créer le dossier **NEXGEN-RH** puis renseigner les paramètres comme suit :
	- Group or Team : `keycloak-hr-empl`, on assigne ici ce dossier au groupe des RHs. Cocher comme droit : **Read**, **Write**, **Delete**, **Share**.
	- Cocher **Advanced Permissions** puis selectionner **Alice Dupont** comme utilisateur qui va gérera ce Dossier. **Alice** aura pourrait interdire ou autoriser telle ou telle action dans ce dossier à un quelconque utilisateur du groupe ayant accès au dossier.

### Etape 4.1 : Création du dossier des Développeurs

- Se connecter en tant qu'admin, puis aller dans **Administration settings**
- Dans le menu de gauche, cliquer sur **Team Folder**
- Créer le dossier **NEXGEN-DEV** puis renseigner les paramètres comme suit :
	- Group or Team : `keycloak-dev-empl`, on assigne ici ce dossier au groupe des RHs. Cocher comme droit : **Read**, **Write**, **Delete**, **Share**.
	- Cocher **Advanced Permissions** puis selectionner **Bob Jackson** comme utilisateur qui va gérera ce Dossier. 

> Avec NextCloud on peut aller plus loin on choisissant un groupe spécifique d'utilisateurs qui pourront administrer le Dossier. 
___

### Etape 4.3 : Vérification

Nous allons vérifier nos configurations sur les dossiers, nous attendons que seuls les utilisateurs du groupe `hr-empl` (l'équipe RH) pourront accéder à leur dossiers, idem pour ceux du groupe `dev-empl` (l'équipe dev).

Nous allons nous connecter sur les comptes de **Bob** et d'**Alice** et vérifier le dossier auquel chacun a accès.

<video width="100%" controls>
  <source src="/videos/rbac-test.webm" type="video/webm">
  Votre navigateur ne supporte pas la lecture de cette vidéo.
</video>

Nous observons là que nos configurations ont été validées ✅.

___

## Étape 5 : Scénario de Validation – Arrivée d'un nouvel employé (Cycle de vie & JIT)

Pour prouver l'**efficacité** et la **robustesse** de cette architecture, nous allons simuler un cas réel d'entreprise, l'**arrivée d'un nouvel employé au sein du département des Ressources Humaines**

L'objectif est de démontrer le concept de **Source Unique de Vérité** et de **Provisioning Just-In-Time (JIT)** : l'administrateur système ne crée l'utilisateur **qu'une seule fois** (dans l'annuaire central FreeIPA). Par la suite, l'employé se connecte et accède instantanément à ses outils et à ses dossiers d'équipe, sans aucune intervention humaine sur Nextcloud.

La vidéo ci-dessous montre :
- La création de l'utilisateur dans FreeIPA et son ajout au groupe global des Ressources Humaines `hr-empl`
- La récupération de l'utilisateur par Keycloak grâce à la Fédération
- La première connexion de l'utilisateur via SSO sur NextCloud : où son compte est créé automatique en l'intégrant au groupe des RHs 
- L'accès direct au dossier **NEXGEN-RH**
- La mise à jour de la liste des utilisateurs de NextCloud 


<video width="100%" controls>
  <source src="/videos/scenar-valid.webm" type="video/webm">
  Votre navigateur ne supporte pas la lecture de cette vidéo.
</video>


___

## Conclusion du Lab 2 : Un modèle IAM souverain, agile et sécurisé

Ce second livrable valide avec succès la mise en œuvre d'une gestion fine et dynamique des accès au sein de l'infrastructure **NexGen**. En passant d'une simple authentification centralisée à un contrôle d'accès basé sur les rôles (RBAC) de bout en bout, nous avons résolu un défi majeur : **concilier la confidentialité des données sensibles et l'automatisation des processus d'ingénierie des identités.**

### 📈 Ce que ce Lab démontre (Les acquis techniques)

L'architecture déployée s'appuie sur trois piliers fondamentaux des infrastructures de sécurité modernes :

1. **Le principe du moindre privilège respecté :** L'étanchéité absolue entre les dossiers d'équipe `NEXGEN-RH` et `NEXGEN-DEV` prouve que le cloisonnement des données confidentielles (comme les salaires ou les spécifications techniques) est désormais une réalité technique inviolable.
2. **Le Just-In-Time (JIT) Provisioning comme standard :** La démonstration de l'arrivée d'une nouvelle recrue illustre la disparition complète des tâches d'administration redondantes. Les comptes applicatifs locaux n'ont plus besoin d'être provisionnés manuellement par un administrateur ; ils sont créés et configurés au moment exact où l'utilisateur initie sa première connexion.
3. **Une source unique de vérité :** Qu'il s'agisse d'une embauche, d'une mutation de service ou d'un changement de droits, **l'annuaire FreeIPA reste le seul et unique point de contrôle**. Keycloak se charge de propager dynamiquement ces modifications à l'écosystème applicatif via les claims du jeton JWT, éliminent ainsi le risque majeur de "comptes fantômes" ou d'accès orphelins.

En finalisant ce Lab 2, NexGen dispose désormais d'une plateforme collaborative moderne, entièrement centralisée, hautement auditable et alignée sur les meilleures pratiques de la gouvernance des identités (IAM).