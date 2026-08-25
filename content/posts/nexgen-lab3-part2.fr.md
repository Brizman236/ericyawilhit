---
title: "Sécurisation d'Active Directory : Enterprise Access Model & Segmentation Administrative (Partie 2)"
date: 2026-08-24T23:24:00Z
draft: false
tags: ["Active Directory", "IAM", "Cybersécurité", "GPO", "Windows Server"]
categories: ["Cybersécurité", "Homelab"]
summary: "Mise en œuvre du modèle d'accès d'entreprise de Microsoft dans Active Directory via la restructuration des OU, la délégation des privilèges administratifs et l'application des GPO de refus d'ouverture de session."
showToc: true
TocOpen: false
cover:
  image: "/images/nexgen-lab3-part2.fr.png"
  relative: false
---

## Introduction
En Partie 1, nous avons audité le domaine et découvert plusieurs vulnérabilités critiques : des identifiants Domain Admin présents sur un poste de travail standard, des comptes de service non-gMSA, une structure d'OU plate et des hôtes résidant dans le conteneur `Computers` par défaut.

Dans ce lab, nous allons résoudre ces vulnérabilités en mettant en œuvre l'Enterprise Access Model de Microsoft. L'objectif est d'isoler les privilèges administratifs, les systèmes et les identifiants dans des périmètres de sécurité distincts basés sur le risque et la criticité. Le principe fondamental est simple : **ne jamais exposer les identifiants d'un compte à haut privilège sur un ordinateur à risque plus faible ou standard**, afin de garantir que si un ordinateur standard est compromis, l'attaquant ne puisse pas extraire ces identifiants de la mémoire.

La mise en œuvre se déroule en 4 étapes principales :

---

## Étape 1 : Restructuration des OU
Du point de vue de la sécurité, le rôle d'une Unité d'Organisation (OU) n'est pas de refléter l'organigramme de l'entreprise, mais de modéliser des périmètres de sécurité. Le regroupement d'objets de même criticité dans des OU dédiées nous permet d'appliquer des Objets de Stratégie de Groupe (GPO) et des règles de délégation sur mesure. 

Voici la structure que nous allons mettre en place :

```text
DC=nexgen,DC=lab
├── OU=NexGen-Tier0
│   ├── OU=Admin-Accounts
│   ├── OU=Admin-Groups
│   ├── OU=Service-Accounts
│   └── OU=Computers (Contrôleurs de domaine)
├── OU=NexGen-Tier1
│   ├── OU=Admin-Accounts
│   ├── OU=Admin-Groups
│   ├── OU=Service-Accounts
│   └── OU=Computers (NXG-SRV-APP01)
└── OU=NexGen-Tier2
    ├── OU=Admin-Accounts
    ├── OU=Admin-Groups
    ├── OU=Computers (NXG-WKS-FIN01, NXG-ADM-IT01)
    └── OU=Standard-Users
        └── OU=NexGen-Infrastructures
            ├── OU=IT
            │   ├── OU=Users
            │   ├── OU=Groups
            └── ... (RH, Finance, R&D, Ventes)
````

### Règles administratives

- **Isolation par Tier :** Chaque Tier aura des comptes administratifs dédiés, assignés strictement à la gestion de son périmètre.
    
      
    
- **Séparation des comptes :** Les administrateurs maintiendront des comptes séparés : un compte standard pour les tâches quotidiennes (ex. e-mail, navigation web) et des comptes administratifs dédiés pour chaque Tier qu'ils gèrent.
    
      
    
- **Catégorisation des utilisateurs :** Tous les comptes d'utilisateurs standards seront alloués sous `Standard-Users`, organisés par département. Au sein de chaque département, les objets sont classés par type d'objet (les comptes utilisateurs dans `Users`, les groupes de sécurité dans `Groups`).
    
      
    

Le script pour cette étape est disponible [ici](https://github.com/Brizman236/Home-Labs/blob/main/02-Identity-Access-Management/02-NexGen-IAM-Infrastructure/Ressources/Scripts/Phase2-Step1.ps1).

  

## Étape 2 : Séparation des privilèges & Délégation

Une vulnérabilité majeure dans les installations Active Directory par défaut est la dépendance à un compte `Domain Admin` unique ou au compte `Administrateur` intégré à pleins privilèges. Ce compte étant très ciblé lors des cyberattaques, sa compromission entraîne la prise de contrôle totale du domaine.

  

Pour réduire la surface d'attaque, nous restreignons l'utilisation quotidienne des comptes Domain Admin grâce à trois contrôles clés :

  

1. **Création de comptes de Tier dédiés :** Attribution de comptes d'administration explicites pour chaque Tier (ex. `adm-user-t0`, `adm-user-t1`, `adm-user-t2`).
    
      
    
2. **Création de groupes de sécurité par Tier :** Création de groupes administratifs (`GG-T0-Admins`, `GG-T1-Admins` et `GG-T2-Admins`).
    
      
    
3. **Délégation des permissions administratives :** Attribution de droits granulaires directement aux groupes de Tier sans les ajouter aux groupes à hauts privilèges intégrés comme `Domain Admins` ou `Enterprise Admins`, en respectant le principe du moindre privilège (PoLP).
    
      
    

### Détail de la délégation de permissions

- **Tier 0 (Identité & Plan de contrôle) :** Les administrateurs de Tier 0 gèrent les contrôleurs de domaine, la PKI et les fournisseurs d'identité (IdP). Comme ces composants contrôlent l'identité sur l'ensemble du domaine, les admins Tier 0 nécessitent un contrôle total sur les objets du domaine et résident dans le groupe `Domain Admins`.
    
      
    
- **Tier 1 (Serveurs & Applications) :** Les administrateurs de serveurs doivent déployer des bases de données, des applications web (ex. Gitea, Nextcloud) et des serveurs métiers sans avoir besoin d'une autorité à l'échelle du domaine. Seuls les droits suivants leur sont délégués : créer/gérer les objets ordinateurs dans `OU=NexGen-Tier1`, gérer les comptes de service gérés par le groupe (gMSA), et contrôler les groupes d'administrateurs locaux de Tier 1.
    
      
    
- **Tier 2 (Postes de travail & Support/Helpdesk) :** Le personnel du support aide les utilisateurs finaux et résout les problèmes des postes de travail au quotidien. Des permissions leur sont accordées uniquement pour : réinitialiser les mots de passe des utilisateurs, déverrouiller les comptes utilisateurs et joindre des ordinateurs dans `OU=NexGen-Tier2`.
    
      
    

Le script pour cette étape est disponible [ici](https://github.com/Brizman236/Home-Labs/blob/main/02-Identity-Access-Management/02-NexGen-IAM-Infrastructure/Ressources/Scripts/Phase2-Step2.ps1).

  

## Étape 3 : Application des GPO de refus d'ouverture de session (Deny Logon)

Nos comptes administratifs étant créés, nous appliquons des restrictions pour empêcher les administrateurs d'un Tier de s'authentifier sur des Tiers d'ordinateurs non autorisés, bloquant ainsi le déplacement latéral et le vol d'identifiants.

  

### Configuration des GPO

1. Ouvrir la **Gestion des stratégies de groupe** (`gpmc.msc`).
    
      
    
2. Sous **Objets de stratégie de groupe**, créer 3 GPO : `Tier0-DenyLogon`, `Tier1-DenyLogon` et `Tier2-DenyLogon`.
    
      
    
3. Pour chaque stratégie, configurer les **Attributions de droits d'utilisateur** suivantes sous :
    
    `Configuration ordinateur` > `Stratégies` > `Paramètres Windows` > `Paramètres de sécurité` > `Stratégies locales` > `Attribution des droits d'utilisateur` :
    
      
    - **Refuser l'ouverture de session en local** (`SeDenyInteractiveLogonRight`)
        
          
        
    - **Refuser l'ouverture de session par les services Bureau à distance** (`SeDenyRemoteInteractiveLogonRight`)
        
          
        
    - **Refuser l'ouverture de session en tant que tâche planifiée (batch)** (`SeDenyBatchLogonRight`)
        
          
        
    - **Refuser l'ouverture de session en tant que service** (`SeDenyServiceLogonRight`)
        
          
        
4. Populer chaque stratégie avec les groupes de sécurité des autres tiers. Par exemple, dans `Tier0-DenyLogon`, ajouter `GG-T1-Admins` et `GG-T2-Admins` aux listes de refus.
    
      
    
5. Lier chaque GPO à son OU cible (ex. lier `Tier0-DenyLogon` à `OU=NexGen-Tier0` et à l'OU intégrée `Domain Controllers`).
    
      
    

## Vérification

Avant d'appliquer les stratégies, un compte administrateur de Tier 1 (`adm-eyawil-t1`) peut s'authentifier et se connecter avec succès sur l'ordinateur de Tier 1 `NXG-WKS-FIN01` :

<video width="100%" controls>
  <source src="/videos/before-denygpo.mp4" type="video/mp4">
  Votre navigateur ne supporte pas la lecture de cette vidéo.
</video>  

Après avoir lié la GPO `Tier0-DenyLogon` et exécuté `gpupdate /force`, les tentatives de connexion de `adm-eyawil-t1` sur le contrôleur de domaine sont explicitement refusées :

  ![](/images/Pasted%20image%2020260824223753.png)


<video width="100%" controls>
  <source src="/videos/after-denygpo.mp4" type="video/mp4">
  Votre navigateur ne supporte pas la lecture de cette vidéo.
</video>

## Prochaines étapes & Améliorations futures

Bien que la restructuration des OU et les GPO de refus de connexion réduisent considérablement l'exposition des identifiants, la sécurisation d'Active Directory est un processus itératif. Dans la **Partie 3**, nous nous appuierons sur cette base de tiering avec les contrôles d'entreprise suivants :

  

1. **Déploiement des comptes de service gérés par le groupe (gMSA) :**
    
      
    - Migrer les comptes de service interactifs vulnérables vers des gMSA afin d'imposer la rotation automatique des mots de passe et de restreindre l'exécution strictly aux SPN des hôtes désignés.
        
          
        
2. **Mise en œuvre de Windows LAPS :**
    
      
    - Déployer LAPS sur tous les serveurs de Tier 1 et postes de travail de Tier 2 pour automatiser la rotation des mots de passe `Administrateur` locaux, éliminant ainsi le déplacement latéral via des identifiants locaux partagés.
        
          
        
3. **Configuration des silos de stratégies d'authentification :**
    
      
    - Configurer les silos et stratégies d'authentification Active Directory pour restreindre l'émission de tickets Kerberos, garantissant ainsi que les comptes de Tier 0 ne puissent pas s'authentifier auprès des SPN de tiers inférieurs même en cas de défaillance des contrôles réseau.
        
          
        
4. **Télémétrie SIEM & Ingestion de détections (Wazuh) :**
    
      
    - Intégrer la journalisation d'audit pour surveiller les tentatives de connexion à travers les tiers. Configurer des alertes pour les échecs d'authentification (ID d'événement 4625) et les escalades explicites de privilèges au sein des groupes de sécurité administratifs.