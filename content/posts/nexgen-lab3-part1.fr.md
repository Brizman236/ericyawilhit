---
title: "Lab 3/5 (Partie 1) : L'Audit d'Urgence Active Directory"
date: 2026-08-21
series: ["NexGen Solution Enterprise Security"]
tags: ["Active Directory", "Audit", "IAM", "Security Engineering"]
description: "Face aux risques de compromission liés à un SSO fédérant un annuaire non durci, ce guide technique détaille l'audit d'urgence d'un domaine Active Directory. À travers un laboratoire pratique utilisant Wazuh, PowerShell et GPO, découvrez comment quantifier les failles d'identités (Kerberoasting, tiering absent, comptes de service vulnérables) avant d'engager la remédiation de l'annuaire source."
draft: false
cover:
  image: /images/lab3-part1.fr.png
  alt: Article Cover
  relative: false
---

## Contexte NexGen Solution

Après le déploiement du SSO souverain avec FreeIPA et Keycloak (Lab 1), puis du RBAC et du provisioning JIT sur Nextcloud (Lab 2), NexGen Solution pensait avoir refermé son problème d'identités éparpillées. La fédération fonctionnait, les accès aux applications étaient centralisés, les revues semblaient sous contrôle.

Puis un audit de routine — motivé par une alerte mineure de Wazuh sur un compte de service au comportement inhabituel — a révélé quelque chose que personne n'avait anticipé : **le SSO fédérait fidèlement des identités qui n'avaient jamais été nettoyées à la source.** Le domaine Active Directory interne de NexGen, utilisé pour les postes de travail et serveurs applicatifs du siège, n'avait jamais été intégré au périmètre des deux premiers labs. Des comptes admin sans justification connue, d'anciens employés toujours activés, une politique de mot de passe unique appliquée aussi bien aux comptables qu'aux administrateurs du domaine — tout ce que la fédération était censée corriger existait encore, intact, un cran plus bas.

Pire : parce que Keycloak fait confiance à ce que l'AD lui transmet, chaque faille locale non corrigée avait été fidèlement propagée vers toutes les applications fédérées. Le SSO n'avait pas résolu le problème d'origine — il l'avait rendu invisible en le déplaçant derrière une façade qui semblait fonctionner.

Ce lab documente la réponse à cet incident : l'audit d'urgence, puis la remédiation complète de l'AD, avec l'obligation de prouver — pas seulement d'affirmer — que la source est désormais fiable avant de pouvoir à nouveau lui faire confiance.

## Les trois problématiques concrètes à résoudre

Reprises directement du contexte NexGen posé au Lab 1 :

1. **Éparpillement des identités et des privilèges** → personne chez NexGen ne peut dire avec certitude qui a des droits d'administrateur du domaine, ni pourquoi
2. **Comptes dormants avec accès actifs** → d'anciens employés ou comptes de test oubliés, toujours activés, jamais révoqués
3. **Faible gestion des mots de passe** → politique de mot de passe unique pour tous les comptes, y compris les comptes à privilèges, sans rotation ni contrôle renforcé

Chaque phase du lab répond à l'une de ces problématiques avec une configuration concrète — pas un exercice théorique.

___
## Environnement

- 1 DC Windows Server (NexGen-DC01) — celui déjà présent dans NexGen-1
- 3 machines simulant : un poste utilisateur standard (service Finance ou RH de NexGen), un poste admin IT, un serveur applicatif interne
- PowerShell + module ActiveDirectory
- Objectif final : cet AD durci devient la source fiable qui sera fédérée à Keycloak dans un futur NexGen Lab

___
### Phase 1 — L'audit d'urgence post-incident

#### 1. Les comptes à priviliès
**Objectif** : Savoir qui peut agir sans limite sur le domaine et pourquoi.

```powershell
# Membres des groupes les plus critiques
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name,
SamAccountName
Get-ADGroupMember -Identity "Enterprise Admins" | Select-Object Name,
SamAccountName
Get-ADGroupMember -Identity "Schema Admins" | Select-Object Name,
SamAccountName

# Administrateurs locaux sur chaque machine (à exécuter sur chaque poste, ou via Invoke-Command à distance)
Get-LocalGroupMember -Group "Administrators"
```

| Poste         | Compte                | Justification connue ?                                                            | Depuis quand ? | Toujours nécessaire ? |
| ------------- | --------------------- | --------------------------------------------------------------------------------- | -------------- | --------------------- |
| DC            | Administrator         | Oui. C'est le compte Administrateur par défaut pour tout domaine Active Directory | Toujours       | Oui et non            |
| NXG-WKS-FIN01 | Mr Robot (Local)      | Oui, c'est le compte utilisé pour la configuration initiale du système            | L'installation | Non                   |
| NXG-WKS-FIN01 | Administrator (Local) | Oui, c'est le compte Administrateur par défaut                                    | L'installation | Oui et non.           |
| NXG-ADM-IT01  | Administrator (Local) | Compte admin par défaut                                                           | L'installation | Oui et non            |
| NXG-ADM-IT01  | Mr Robot (Local)      | Compte utilisé pour la configuration initiale                                     | L'installation | Non                   |
| NXG-SRV-APP01 | Administrator (Local) | Compte admin par défaut                                                           | L'installation | Non                   |

#### Analyse des résultats

- Sur le DC, nous remarquons qu'il n'y a qu'un seul compte à privilège, ce n'est autre que le compte administrateur par défaut, **Administrator**. Ce compte présente plusieurs risque pour l'infrastructre AD :
	- Tout d'abord, le fait qu'il en existe qu'un seul obligerait tous les adminsitrateurs de l'entreprise à le partager pour effectuer des tâches d'administrations. De ce fait, il y aura aucune traçabilité pour savoir qui a fait quoi dans le domaine et même si c'est un attaquant. Il faudrait avoir plusieurs comptes admin pour chaque administrateur du domaine.
	- Ensuite, le nom étant universel, ce compte est beaucoup plus visé par les attaques par brutes forces, l'attaquant ne perdant pas de temps à essayer de déviner le nom d'un compte du domaine. Garder le nom tel quel augmente son risque de compromission ce qui peut entraîner la compromission de toute l'entreprise. Il faudrait le renommer et le désactiver, ne l'utiliser que temporairement pour des cas critiques comme la perte de tous les autres comptes admins.
	
- Sur les postes et le serveur applicatif :
	- le compte **Administrator** par défaut est présent. Comme précédement, ce dernier présente aussi un risque : son nom est universel et peut être victime des attaques brute force. Une renommation et une désactivation sont nécessaires. 
	- On trouve le groupe **Domain Admins**. La présence de ce groupe nous dit qu'un membre peut s'y connecter et avoir tous les droits d'administrateurs. Cela nous pose un problème de Tiering. C'est-à-dire que, dans le cas où un Domain Admin se connecterait à ces machines, un attaquant ayant compromis le compte de l'utilsateur (via du phishing par exemple, ce qui est quelque peu fréquent) peut élever ces privilèges et voler les Tickets Kerberos ou des Hash NTLM d'un Domain Admin. Il aura ainsi les droits de domain Admin, de ce fait, toute l'infrastructure de l'entreprise se retrouvera compromise.
___
#### 2. Les comptes de services
**Objectif** : Vérifier qu'aucun compte de service n'a plus de droits que nécessaires.

Un compte de service :
- Doit avoir un mot de passe qui n'expire jamais d
```powershell
# Les comptes de services ont un SPN enregistré
Get-ADUser -Filter {servicePrincipalName -like "*"} -Properties ServicePrincipalName | Select-Object Name, servicePrincipalName
```

![](/images/Pasted%20image%2020260724163120.png)

Nous avons un compte de service qui est `svc-nexgen-webapp` avec le SPN `HTTP/NXG-SRV-APP01`. Des analyses sont nécessaires pour déterminer si :
- Le compte n'a pas de logon interactif : un compte de service est un compte utilisé par un programme de manière automatisée afin d'effectuer des tâches. De ce fait, il n'y a pas besoin à ce qu'un utilisateur standard se connecte en l'utilisant. En vue de respecter le principe du moindre privilège, le compte ne doit pas posséder cette fonctionnalité
- Le compte doit disposer d'un mot de passe qui ne s'expire jamais quoique cette configuration expose certaines vulnérabilités. Comme dit précédement, ce compte est utilisé de manière automatisée, de ce fait si le mot de passe est expiré, le service étant non humain ne saurait comment modifier son mot de passe. Cependant cela comporte un risque, si un attaquant arrive à voler les idpropreentifiants de ce compte sans que cela ne se sache, il pourra usurper indéfiniement l'identité de ce service, le mot de passe ne s'expirant jamais. La solution idéale sera un compte **gMSA** (Le concept sera développé ultérieurement)
- Le compte ne doit disposer que des privilèges nécessaires à sa tâche
- Le compte doit disposer d'un mot de passe fort afin d'éviter le craquage pour du Kerberoasting

##### 2.1 Vérification des politiques appliquées

```powershell
# Depuis NXG-SRV-APP01
gpresult /h C:\rapport-gpo-nxg-srv-app01.html
```

![](/images/Pasted%20image%2020260727104152.png)

![](/images/Pasted%20image%2020260727104759.png)

| Constat                                                                                   | Risque business                                                                                                                                                                     | Remédiation prévue                                                                                   |
| ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Aucune GPO de restriction sur `NXG-SRV-APP01` ; seule la Default Domain Policy s'applique | Le compte de service peut aujourd'hui ouvrir une session interactive comme n'importe quel compte humain, ce qui élargit sa surface d'exploitation si son mot de passe est compromis | Créer et lier une GPO dédiée avec `Deny log on locally` / `Log on as a service`                      |
| Une faible politique de mot de passe avec 7 caractères minimum                            | Le compte de service peut être compromis car son mot de passe est qlq peu craquable                                                                                                 | Renforcer la politique de mot de passe allant jusqu'à 14 caractères minimum et configuration du gMSA |

##### 2.2 Vérification de l'expiration du mot de passe du compte

```powershell
Get-ADUser -Identity "svc-nexgen-webapp" | Select-Objet PasswordNeverExpires
```

![](/images/Pasted%20image%2020260727105644.png)

Le mot de passe ne s'expirera jamais. Avant de continuer, il est nécessaire de vérifier si ce compte est un gMSA ou non. Pour ce faire, la commande ci-dessous est à exécuter :

```powershell
Get-ADServiceAccount -Identity "svc-nexgen-webapp"
```

![](/images/Pasted%20image%2020260727110859.png)

Le compte `svc-nexgen-webapp` n'en est pas un.

___
##### Synthèse

| #   | Constat                                                                                                                       | Risque business                                                                                                                                    | Remédiation prévue                                                                              |
| --- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| 1   | Le compte `svc-nexgen-webapp` possède un SPN (`HTTP/NXG-SRV-APP01`)                                                           | Expose le compte au Kerberoasting — tout utilisateur authentifié du domaine peut demander un ticket et tenter de casser le mot de passe hors ligne | Renforcer le mot de passe + migration gMSA (élimine le risque, mot de passe de 240 caractères)  |
| 2   | Aucune GPO de restriction sur `NXG-SRV-APP01` ; seule la Default Domain Policy s'applique                                     | Le compte de service peut ouvrir une session interactive comme un compte humain, élargissant sa surface d'exploitation si compromis                | Créer et lier une GPO dédiée avec `Deny log on locally` / `Log on as a service`                 |
| 3   | Politique de mot de passe du domaine à 7 caractères minimum, appliquée sans distinction au compte de service                  | Mot de passe faible plus facilement cassable, notamment via Kerberoasting (lien direct avec le constat n°1)                                        | Renforcer à 14 caractères minimum, idéalement via FGPP différenciée pour les comptes de service |
| 4   | `PasswordNeverExpires = $true` confirmé sur le compte                                                                         | Un mot de passe compromis reste valide indéfiniment, sans rotation possible sans intervention humaine                                              | Migration vers gMSA (rotation automatique tous les 30 jours)                                    |
| 5   | Le compte n'est **pas** un gMSA (confirmé via `Get-ADServiceAccount`) — c'est un objet `user` classique créé via `New-ADUser` | Cumule tous les risques ci-dessus (2, 3, 4) puisqu'aucune des protections natives d'un gMSA ne s'applique                                          | Migration complète vers un vrai gMSA via `New-ADServiceAccount`                                 |

___

#### 3. Structure des OUs et objets non classés

Les objectifs de cette 3e phase sont de :
- Vérifier si des objets figurent dans les OUs par défaut
- Vérifier la structure actuelle des OUs dans le domaine

##### 3.1 Les objets figurant dans les OUs par défaut

```powershell
# Objets restés dans les conteneurs par défaut (non gérés par GPO)
Get-ADUser -Filter * -SearchBase "CN=Users,DC=nexgen,DC=lab" |
Select-Object Name, DistinguishedName
Get-ADComputer -Filter * -SearchBase "CN=Computers,DC=nexgen,DC=lab" | Select-Object Name, DistinguishedName
```

![](/images/Lab%204%20IAM/Pasted%20image%2020260727234803.png)

On peut constater que :
- Dans l'OU **Users**, on y trouve que des comptes par défaut du domaine, sensé y être d'ailleurs. Pas de souci de ce côté.
- Les machines du domaines sont toutes présentent dans l'OU par défaut **Computers**. De ce fait, il est impossible de les gérer par des GPOs.
 
 **Problème démontré  :** Précédement nous avons eu à présenter le risque de la présence du groupe **Domain Admins** sur les postes utilisateurs. En effet, la présence de ce groupe signifie qu'un administrateur du domaine (utilisateur ayant tous les droits sur l'ensemble du domaine) peut se connecter et se faire voler ses tickets Kerberos. La remédiation de ce risque serait d'appliquer une politique à l'ensemble des postes utilisateurs afin d'interdire cette connexion. Cependant cela n'est pas possible parce que ces postes sont dans l'OU **Computers**. 

**Décision et Justification :** Il est nécessaire de déplacer les 3 machines depuis le conteneur par défaut `CN=Computers` vers une OU dédiée permettant l'application de GPO. Ce déplacement est un prérequis technique indispensable — sans lui, aucune politique de sécurité ne peut être appliquée aux postes du domaine, quelle que soit la qualité de cette politique. 

##### 3.2 La structure des OUs

```powershell
# Récupérer tous les OUs du domaine
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
```

![](/images/Pasted%20image%2020260802164045.png)

De part cette structure, nous remarquons la présence d'une OU parente `NexGen-Infrastructes` représentant, comme son nom l'indique l'unité d'organisation de tous les objects composant l'infrastructure de **Nex Gen**. De plus, nous y trouvons d'autres OUs représentant chaque département de **Nex Gen**. 

Nous allons ensuite consulter quels objets sont repertoriés dans ces OUs :

```powershell
Get-ADObject -SearchBase "OU=NexGen-Infrastructures,DC=nexgen,DC=lab" -Filter 'ObjectClass -ne "organizationalUnit"'
```

![](/images/Pasted%20image%2020260802165523.png)

En consultant l'inventaire des objets figurant dans `NexGen-Infrastructures`, nous remarquons la présence des groupes et des utilisateurs dans chaque OU/Département, chaque département ayant son groupe d'utilisateur. Il y a aucune séparation entre les différentes classes d'objets.

**Problèmes démontrés** : Cette abscence de séparation soulève deux problèmes d'ordre majeurs. 
1. Un problème de **lisibilité** et de **gestion** : Nex Gen en tant qu'entreprise florissante embauchera de plus en plus d'employé dans chaque département. Ces employés, dans l'état actuel des choses, seront rangés dans leur OU respectif, mélangés avec les Groupes. Quand il s'agirait d'attribuer des droits ou de gérer des objets selon leur type ou classe, il sera difficile pour l'administrateur de distinguer et d'indentifier les groupes parmi les nombreux utilisateurs. D'où le problème de **lisibilité** et de **gestion**. 
2. Un problème de **rigidité structurelle** : si l'on reste dans le même contexte précédemment énoncé, les employés embauchés par Nex Gen auront une certaine disparité de rôles dans leur département respectif. Cependant, dans l'état actuel il n'existe qu'un seul groupe englobant tous les membres d'un même département
3. Un manque de **granularité** : Les groupes actuelles sont un mélange de deux choses dans un seul objet : la fonction d'un utilisateur (son rôle dans l'entreprise) et l'accès à une ressource précise, sans jamais les séparer. Imaginons que le département R&D ait besoin d'accéder au serveur application du département IT pour un projet de courte durée. Deux options s'offrent à nous : 
	- Attribuer directement les droits d'accès au groupe R&D : Avec cette option, les droits d'accès devront être attribués à chaque département ou particulier comme un auditeur ayant besoin d'accéder à ce serveur (allourdissement du travail). Lorsqu'il s'agira de retirer les utilisateurs n'ayant plus besoin de ces accès, l'administrateur devra inspecter chaque groupe pour vérifier s'il a les droits ou non.
	- Ajouter R&D dans le groupe des IT : cela leur donnerait, en plus des droits d'accès au serveur applicatif, d'autres droits supplémentaires propres au département IT. Ce qui est une violation du principe de moindre privilège.
	Comme on peut le constater, ces deux options soulèvent encore d'autres problématiques.

**Décision et Justification** : 
1. Afin de remédier au problème de **lisibilité** et de **gestion**, nous allons, dans chaque OU ou département, séparer les objets selon leur type. C'est-à-dire créer des sous-OUs **Users/Groups/Computers** . 
2. Quant aux deux derniers problèmes, nous allons créer deux types de groupes : des groupes de **rôle** (représentant la fonction de l'utilisateur dans l'entreprise) et des groupes de **ressources** (représentant les accès à des ressources). Avec cette structure, pour pouvoir donner des accès à une ressource comme le serveur applicatif, il suffit juste d'ajouter soit l'utilisateur ou un groupe d'utilisateur ayant le même rôle (un groupe de rôle, ex. `gg-IT-User`) au groupe de ressource (ex. `gg-Res-SrvApp`). L'ajout et la révocation des accès se feront au même endroit.


___

#### Synthèse

| #                                                    | Constat                                                                  | Risque business                                                                                            | Remédiation                                      | Lien avec les autres findings                                                               |
| ---------------------------------------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| **Groupe A — Absence de criticité (Tiering)**        |                                                                          |                                                                                                            |                                                  |                                                                                             |
| 1                                                    | `Domain Admins` présent dans les admins locaux de `NXG-WKS-FIN01`        | Chemin d'attaque complet possible : phishing → vol de ticket Kerberos → compromission du domaine           | Modèle Tier 0/1/2 avec `Deny log on locally`     | Rendu possible par l'absence de structure permettant d'isoler les niveaux de criticité (#2) |
| 2                                                    | Aucune OU par criticité ; structure organisée uniquement par département | Aucune barrière structurelle n'empêche un compte à haut privilège de se connecter n'importe où             | Créer `NexGen-Tier0/1/2`                         | Cause directe du finding #1                                                                 |
| **Groupe B — Objets mal rangés (blocage technique)** |                                                                          |                                                                                                            |                                                  |                                                                                             |
| 3                                                    | Les 3 machines sont dans `CN=Computers` (conteneur par défaut)           | Aucune GPO ne peut leur être appliquée, y compris la remédiation du finding #1                             | Déplacer vers une OU réelle                      | Bloque directement la remédiation du finding #1                                             |
| **Groupe C — Structure des groupes**                 |                                                                          |                                                                                                            |                                                  |                                                                                             |
| 4                                                    | Mélange Users/Groups dans chaque OU département                          | Lisibilité et délégation compromises à mesure que NexGen grandit                                           | Sous-OUs Users/Groups/Computers par département  | Indépendant du Tiering — un problème d'organisation, pas de criticité                       |
| 5                                                    | Groupes plats (`gg-IT-Users`) mélangeant rôle et ressource               | Chaque changement d'accès devient coûteux ; violation du moindre privilège en cas de besoin d'accès croisé | Groupes de rôle séparés des groupes de ressource | Complète le finding #4 — même cause (structure jamais pensée pour la croissance)            |

___

## Prochaines Étapes : Plan de Remédiation

Après avoir démontré l'insécurité de notre annuaire source, l'étape suivante consiste à le durcir. Dans **Lab 3 - Partie 2**, nous déploierons le modèle de **Tiering Active Directory**, la séparation des OUs par criticité et l'isolation des comptes à privilèges.