---
title: "Sécurisation d'Active Directory : Protection des identités, des identifiants et de l'authentification (Partie 3)"  
date: 2026-09-01T00:00:00Z  
draft: false  
tags: ["Active Directory", "IAM", "Cybersécurité", "Windows LAPS", "gMSA", "Kerberos"]  
summary: "Mise en œuvre pratique du durcissement d'Active Directory sous l'angle IAM, avec la migration vers les gMSA, Windows LAPS et le durcissement des politiques d'authentification."  
showToc: true  
TocOpen: false  
cover:  
  image: "/images/nexgen-lab3-part3.fr.png"  
  relative: false
---
## Introduction

Dans la [Partie 2](https://ericyawilhit.netlify.app/posts/nexgen-lab3-part2/), nous avons établi des frontières et des politiques visant à contenir les privilèges administratifs. Ces mesures nous ont permis de corriger plusieurs faiblesses identifiées lors de la phase d'audit, présentée dans la [Partie 1](https://ericyawilhit.netlify.app/posts/nexgen-lab3-part1/). Mais notre environnement est-il pour autant complètement sécurisé ?

Bien que nous ayons mis en place plusieurs contrôles de sécurité, certaines faiblesses importantes subsistent :

- Le modèle de **tiering** protège les identités privilégiées, mais qu'en est-il des **identités utilisées par les comptes de service** ?
    
- Les politiques de refus d'ouverture de session restreignent les endroits où les comptes administratifs peuvent s'authentifier. Mais qu'en est-il des **comptes administrateurs locaux** ?
    
- La séparation des privilèges limite l'impact d'une compromission, mais que se passe-t-il si les **identifiants eux-mêmes sont compromis** ?
    
- Nos politiques d'authentification doivent également fournir une protection suffisante contre les **attaques basées sur les mots de passe et les abus des mécanismes d'authentification**.
    

En d'autres termes, nous avons établi des **frontières autour des accès administratifs**, mais nous n'avons pas encore suffisamment sécurisé les **identifiants et les mécanismes d'authentification** qui se trouvent derrière ces accès.

Cette partie se concentrera donc sur trois domaines complémentaires : **la protection des comptes de service, la gestion des identifiants locaux et le renforcement de l'authentification**.

Nous traiterons ces problématiques à travers :

- **gMSA**, afin d'éliminer la gestion manuelle des mots de passe des comptes de service ;
    
- **Windows LAPS**, afin de centraliser et d'automatiser la gestion des identifiants des administrateurs locaux ;
    
- **les politiques de mot de passe, de verrouillage des comptes et Kerberos**, afin de renforcer le niveau de sécurité de l'authentification au sein du domaine.

---

### Étape 1 : Migrer le compte de service de l'application Web vers un gMSA

Notre compte de service présente une faiblesse importante : il utilise un mot de passe statique qui n'expire pas. Cela augmente le risque de compromission du compte et le rend vulnérable à des attaques telles que le **Kerberoasting**.

Pour corriger cette faiblesse, nous allons migrer le compte utilisateur standard vers un **Group Managed Service Account** (**gMSA**).

Ce choix présente plusieurs avantages :

- Le mot de passe du gMSA est géré par Active Directory plutôt que par un administrateur humain.
    
- Le mot de passe du gMSA est long et généré aléatoirement, ce qui rend son cassage hors ligne beaucoup plus difficile.
    
- Le mot de passe n'a pas besoin d'être saisi ou utilisé manuellement par un administrateur.
    
- Le mot de passe est automatiquement renouvelé sans intervention humaine.
    

**Comment pouvons-nous mettre cela en œuvre ?**

La migration nécessite plusieurs étapes :

- Le mot de passe du gMSA est généré et géré par le **Key Distribution Service (KDS)**, qui repose sur une **KDS Root Key**. Une KDS Root Key doit donc être disponible dans le domaine.
    
- Afin de pouvoir récupérer le mot de passe géré, `NXG-SRV-APP01` doit être autorisé à utiliser le gMSA. Plutôt que d'attribuer directement cette permission au compte ordinateur, nous avons créé un groupe de sécurité dédié, `GG-NXG-SRV-APP-gMSA-Hosts`, et lui avons accordé la permission de récupérer le mot de passe géré du gMSA.
    
- Après sa création, le gMSA doit être installé sur le serveur cible afin que celui-ci puisse utiliser le compte.
    
- Enfin, nous avons configuré le pool d'applications IIS afin qu'il utilise `gmsa-nxg-webapp$` comme identité.
    

### Vérification

![](/images/Pasted%20image%2020260830112035.png)

![](/images/Pasted%20image%2020260830113245.png)

![](/images/Pasted%20image%2020260830093958.png)

![](/images/Pasted%20image%2020260830095013.png)

Nous avons vérifié que :

- Le gMSA a été correctement créé en tant que `msDS-GroupManagedServiceAccount`.
    
- `NXG-SRV-APP01` a été autorisé à récupérer son mot de passe géré.
    
- Le gMSA a été correctement installé sur `NXG-SRV-APP01`.
    
- `Test-ADServiceAccount` a retourné `True`.
    
- Le pool d'applications IIS a été configuré pour utiliser `NEXGEN\gmsa-nxg-webapp$`.
    
- Les SPN HTTP ont été correctement associés au gMSA, tandis que l'ancien compte de service ne les possède plus.
    

À la fin de la migration, la gestion du mot de passe est retirée des mains des administrateurs et confiée à Active Directory. Cela réduit considérablement les risques liés aux identifiants de service statiques et permet d'atténuer l'exposition au Kerberoasting identifiée lors de l'audit initial.

---

## Étape 2 : Protéger les identifiants des administrateurs locaux avec Windows LAPS

Dans notre architecture, nous avons sécurisé les comptes de domaine à privilèges élevés grâce à la mise en œuvre du **modèle de tiering**. Cependant, d'autres comptes privilégiés nécessitent également notre attention : les **comptes administrateurs locaux**.

Ces comptes disposent de privilèges administratifs complets sur leurs machines respectives, mais aucun mécanisme centralisé ne permet actuellement de gérer leurs identifiants.

Quelqu'un doit donc décider :

- Quel doit être le mot de passe de chaque compte ?
    
- Où doit-il être stocké ?
    
- Quand doit-il être changé ?
    
- Qui est autorisé à le récupérer ?
    
- Comment pouvons-nous savoir qui l'a récupéré ?
    

Tout doit être géré manuellement par des humains.

La solution consiste à mettre en œuvre **Local Administrator Password Solution (LAPS)**.

**LAPS** est une fonctionnalité Windows qui automatise le cycle de vie du mot de passe d'un administrateur local :

- L'ordinateur génère un nouveau mot de passe.
    
- LAPS stocke le mot de passe dans Active Directory.
    
- Le mot de passe du compte administrateur local est modifié.
    
- Le mot de passe atteint sa date d'expiration.
    
- LAPS génère un nouveau mot de passe.
    
- Le processus recommence.
    

Grâce à LAPS, nous pouvons définir des politiques régissant le cycle de vie du mot de passe, notamment :

- Sa longueur et sa complexité.
    
- La fréquence de rotation du mot de passe.
    
- Les administrateurs autorisés à récupérer le mot de passe stocké pour le compte administrateur local d'un ordinateur donné.
    

Cela supprime la gestion manuelle des mots de passe des administrateurs et introduit un processus centralisé, contrôlé et auditable pour les identifiants privilégiés locaux.

### 1. Mettre en œuvre Windows LAPS

Windows LAPS fournit deux modes de gestion des comptes :

- **Gestion manuelle du compte :** l'administrateur IT est responsable de la création et de la configuration du compte local cible. Windows LAPS se contente d'en gérer le mot de passe.
    
- **Gestion automatique du compte :** Windows LAPS gère l'ensemble du cycle de vie du compte cible. Il peut créer un compte personnalisé, configurer ses propriétés, l'ajouter au groupe Administrateurs local, l'activer ou le désactiver et faire tourner automatiquement son mot de passe.
    

Pour ce lab, nous utiliserons la **gestion automatique du compte** avec un compte administrateur local personnalisé.

Cela nous permet de conserver le compte Administrator intégré inutilisé et désactivé tout en disposant d'un compte administrateur distinct, géré par LAPS, pour les accès d'urgence ou les opérations administratives.

#### 1.1 Préparer Active Directory

Avant de configurer Windows LAPS, nous devons étendre le schéma Active Directory avec les attributs nécessaires au stockage des informations liées aux comptes gérés par LAPS.

```powershell
Import-Module LAPS

Update-LapsADSchema
```

L'extension du schéma n'est nécessaire qu'une seule fois pour le domaine.

Nous devons ensuite déléguer les permissions nécessaires.

Windows LAPS nécessite deux types de permissions :

1. **Permission d'auto-écriture de l'ordinateur** — permet aux ordinateurs de mettre à jour leurs propres attributs LAPS dans Active Directory.
    
2. **Permission de récupération du mot de passe** — détermine quels administrateurs sont autorisés à récupérer les mots de passe stockés.
    

Nous accordons d'abord aux ordinateurs présents dans nos OU Tier 1 et Tier 2 la permission de mettre à jour leurs propres attributs LAPS :

```powershell
Set-LapsADComputerSelfPermission `
    -Identity "OU=Computers,OU=NexGen-Tier1,DC=nexgen,DC=lab"

Set-LapsADComputerSelfPermission `
    -Identity "OU=Computers,OU=NexGen-Tier2,DC=nexgen,DC=lab"
```

Cela permet de séparer clairement la **capacité à écrire les informations LAPS** de la **capacité à lire les mots de passe LAPS**.

#### 1.2 Contrôler la récupération des mots de passe LAPS

La rotation des mots de passe n'est pas suffisante. Nous devons également contrôler qui peut récupérer les identifiants stockés dans Active Directory.

Plutôt que d'accorder directement les permissions de lecture des mots de passe à des administrateurs individuels, nous allons utiliser des groupes de sécurité dédiés :

```text
GG-NXG-T1-LAPS-Readers
GG-NXG-T2-LAPS-Readers
```

Ces groupes contiendront les groupes administratifs autorisés à récupérer les mots de passe LAPS des ordinateurs appartenant à leur tier respectif.

```powershell
New-ADGroup `
    -Name "GG-NXG-T1-LAPS-Readers" `
    -SamAccountName "GG-NXG-T1-LAPS-Readers" `
    -GroupCategory Security `
    -GroupScope Global `
    -Path "OU=Admin-Groups,OU=NexGen-Tier1,DC=nexgen,DC=lab"

Add-ADGroupMember `
    -Identity "GG-NXG-T1-LAPS-Readers" `
    -Members "GG-T1-Admins"
```

Et pour le Tier 2 :

```powershell
New-ADGroup `
    -Name "GG-NXG-T2-LAPS-Readers" `
    -SamAccountName "GG-NXG-T2-LAPS-Readers" `
    -GroupCategory Security `
    -GroupScope Global `
    -Path "OU=Admin-Groups,OU=NexGen-Tier2,DC=nexgen,DC=lab"

Add-ADGroupMember `
    -Identity "GG-NXG-T2-LAPS-Readers" `
    -Members "GG-T2-Admins"
```

Nous pouvons ensuite déléguer la capacité à récupérer les mots de passe LAPS :

```powershell
Set-LapsADReadPasswordPermission `
    -Identity "OU=NexGen-Tier1,DC=nexgen,DC=lab" `
    -AllowedPrincipals @("NEXGEN\GG-NXG-T1-LAPS-Readers")

Set-LapsADReadPasswordPermission `
    -Identity "OU=NexGen-Tier2,DC=nexgen,DC=lab" `
    -AllowedPrincipals @("NEXGEN\GG-NXG-T2-LAPS-Readers")
```

Cela signifie que la récupération des mots de passe est contrôlée indépendamment de l'administration des serveurs.

Par exemple, un administrateur Tier 1 peut administrer un serveur Tier 1 sans obtenir automatiquement le droit de récupérer tous les mots de passe LAPS. Seuls les membres du groupe LAPS Reader dédié disposent de cette permission.

#### 1.3 Configurer les politiques LAPS

Les politiques LAPS seront appliquées aux ordinateurs **Tier 1 et Tier 2**.

Nous allons donc créer deux GPO :

```text
Tier1-LAPS
Tier2-LAPS
```

![](/images/Pasted%20image%2020260830193629.png)

Ces politiques configurent le client Windows LAPS sur les ordinateurs appartenant à leurs tiers respectifs.

Entre autres paramètres, nous allons configurer Windows LAPS afin de :

- utiliser la **gestion automatique du compte** ;
    
- créer un compte administrateur local personnalisé ;
    
- ajouter le compte au groupe Administrateurs local ;
    
- générer un mot de passe aléatoire robuste ;
    
- faire tourner automatiquement le mot de passe ;
    
- sauvegarder le mot de passe dans Active Directory ;
    
- contrôler l'état activé ou désactivé du compte selon les exigences de sécurité définies.
    

![](/images/Pasted%20image%2020260830192854.png)

Le résultat est un compte administrateur local dont le cycle de vie du mot de passe ne dépend plus d'une gestion humaine.

#### 1.4 Désactiver le compte Administrator intégré

Bien que Windows LAPS puisse gérer le compte Administrator intégré, nous avons délibérément choisi d'utiliser un **compte personnalisé distinct**.

Le compte Administrator intégré sera donc désactivé via une GPO dédiée :

```text
Disabling Built-in Admin Account
```

Cette GPO est liée aux OU contenant les ordinateurs Tier 1 et Tier 2.

La stratégie concernée est :

```text
Computer Configuration
    └── Policies
        └── Windows Settings
            └── Security Settings
                └── Local Policies
                    └── Security Options
                        └── Accounts:
                            Administrator account status
```

Nous configurons cette stratégie sur :

> **Disabled**

Cela permet de séparer clairement les deux contrôles :

```text
Windows LAPS
    │
    ├── Crée le compte administrateur local personnalisé
    ├── Génère le mot de passe
    ├── Fait tourner le mot de passe
    └── Stocke le mot de passe dans AD

GPO de durcissement des comptes locaux
    │
    └── Désactive le compte Administrator intégré
```

Après application de la stratégie, nous pouvons vérifier son état effectif sur `NXG-SRV-APP01` :

```powershell
Get-LocalUser -Name "Administrator" |
    Select-Object Name, Enabled, PasswordLastSet
```

Le résultat attendu est :

```text
Name            Enabled
----            -------
Administrator   False
```

Nous pouvons également vérifier que la GPO correspondante a bien été appliquée :

```powershell
gpresult /r /scope computer
```

![](/images/Pasted%20image%2020260901122220.png)

À ce stade, le compte Administrator intégré est désactivé tandis que notre compte administrateur personnalisé, géré par LAPS, reste disponible conformément à la politique LAPS configurée.

### 2.5 Valider la récupération du mot de passe

Enfin, nous devons vérifier non seulement que LAPS gère correctement le compte, mais également que notre **modèle d'autorisation** fonctionne comme prévu.

Depuis un compte administrateur Tier 1 autorisé, nous pouvons récupérer le mot de passe d'un ordinateur Tier 1 :

```powershell
Get-LapsADPassword -Identity "NXG-SRV-APP01" -AsPlainText
```

![](/images/Pasted%20image%2020260830224241.png)

Le point important ici est que le mot de passe n'est pas simplement « disponible dans Active Directory ». Son accès est contrôlé par les permissions que nous avons déléguées précédemment.

Notre modèle final est donc le suivant :

```text
                    Active Directory
                           │
              ┌────────────┴────────────┐
              │                         │
       Ordinateurs Tier 1        Ordinateurs Tier 2
              │                         │
              ▼                         ▼
        Windows LAPS              Windows LAPS
              │                         │
              ▼                         ▼
   Administrateur local         Administrateur local
       personnalisé                 personnalisé
              │                         │
              └────────────┬────────────┘
                           │
                    Mot de passe LAPS
                           │
                  ┌────────┴────────┐
                  │                 │
          T1 LAPS Readers    T2 LAPS Readers
```

Avec cette implémentation, nous avons traité deux risques liés aux identifiants locaux : **la gestion manuelle des mots de passe administrateurs locaux** et l'utilisation persistante du **compte Administrator intégré bien connu**.

---

## Étape 3 : Durcir les politiques d'authentification

Après avoir sécurisé les comptes de service et les identifiants des administrateurs locaux, la couche suivante consiste à renforcer les mécanismes d'authentification utilisés par les utilisateurs du domaine.

Pour cette étape, nous allons configurer trois politiques appliquées à l'échelle du domaine :

- **Politique de mot de passe**
    
- **Politique de verrouillage des comptes**
    
- **Politique Kerberos**
    

Ces politiques seront configurées dans la **Default Domain Policy**, puisqu'elles ont vocation à établir des exigences d'authentification communes à l'ensemble du domaine NexGen.

---

#### 3.1 Politique de mot de passe

La première couche est la politique de mot de passe. Bien que la robustesse des mots de passe ne puisse pas, à elle seule, fournir une protection complète contre les attaques visant les identifiants, elle reste une couche de défense importante pour les comptes dont les mots de passe sont gérés par des humains.

Nous avons configuré les paramètres suivants :

|Politique|Configuration|
|---|--:|
|Historique des mots de passe|**24 mots de passe**|
|Durée de vie maximale du mot de passe|**42 jours**|
|Âge minimal du mot de passe|**1 jour**|
|Longueur minimale du mot de passe|**14 caractères**|
|Le mot de passe doit respecter les exigences de complexité|**Activé**|
|Stocker les mots de passe avec un chiffrement réversible|**Désactivé**|

La combinaison de la longueur minimale, des exigences de complexité et de l'historique des mots de passe rend les attaques par devinette et la réutilisation des mots de passe plus difficiles, tandis que la durée de vie maximale limite la période pendant laquelle un mot de passe compromis peut rester valide.

Après avoir configuré la politique, nous avons forcé une mise à jour des stratégies de groupe :

```powershell
gpupdate /force
```

Nous avons ensuite vérifié la politique de mot de passe effective du domaine :

```powershell
net accounts
```

La configuration obtenue confirme que la politique a bien été appliquée :

```text
Minimum password age (days):                          1
Maximum password age (days):                          42
Minimum password length:                              14
Length of password history maintained:                24
```

---

#### 3.2 Politique de verrouillage des comptes

Une politique de mot de passe robuste n'empêche pas un attaquant d'effectuer plusieurs tentatives d'authentification contre un compte.

Pour limiter les attaques par **brute force** et **password spraying**, nous avons configuré la **politique de verrouillage des comptes**.

Les valeurs suivantes ont été sélectionnées :

|Politique|Configuration|
|---|---|
|Seuil de verrouillage du compte|**5 tentatives invalides**|
|Durée de verrouillage du compte|**15 minutes**|
|Réinitialisation du compteur de verrouillage après|**15 minutes**|

Cela signifie qu'après cinq tentatives d'authentification incorrectes consécutives, le compte est temporairement verrouillé pendant 15 minutes.

La fenêtre d'observation est également configurée à 15 minutes. Le compteur de tentatives échouées est donc réinitialisé après 15 minutes sans atteindre le seuil de verrouillage.

Cette politique offre ainsi une protection contre les tentatives d'authentification répétées tout en évitant des périodes de verrouillage excessivement longues.

Cependant, le verrouillage des comptes doit être configuré avec précaution. Un attaquant pourrait volontairement provoquer le verrouillage des comptes d'utilisateurs légitimes, transformant ainsi ce mécanisme en vecteur de **déni de service**. Les valeurs doivent donc être adaptées aux exigences opérationnelles et de sécurité de l'organisation.

Après avoir appliqué la politique :

```
gpupdate /force
```

nous avons vérifié la configuration effective :

```
net accounts
```

La sortie confirme :

```
Lockout threshold:                                    5
Lockout duration (minutes):                           15
Lockout observation window (minutes):                15
```

---

#### 3.3 Politique Kerberos

Le dernier composant de notre durcissement de l'authentification est la **politique Kerberos**.

Kerberos est le principal protocole d'authentification utilisé par Active Directory. Bien que notre configuration précédente utilise déjà des mécanismes de chiffrement Kerberos modernes tels que **AES-256**, la sécurité de l'authentification dépend également de la durée de validité des tickets Kerberos et de la manière dont le KDC applique certaines restrictions d'authentification.

Les paramètres suivants ont été configurés :

|Politique Kerberos|Configuration|
|---|---|
|Appliquer les restrictions d'ouverture de session utilisateur|**Activé**|
|Durée de vie maximale d'un ticket de service|**600 minutes**|
|Durée de vie maximale d'un ticket utilisateur|**10 heures**|
|Durée maximale de renouvellement d'un ticket utilisateur|**7 jours**|
|Tolérance maximale pour la synchronisation de l'horloge des ordinateurs|**5 minutes**|

Ces paramètres contrôlent la durée de vie des tickets Kerberos ainsi que la période pendant laquelle ils peuvent être renouvelés.

Par exemple, le processus d'authentification d'un utilisateur peut être représenté ainsi :

```
Utilisateur
  │
  │ Authentification
  ▼
KDC
  │
  ├── TGT
  │     └── Valide jusqu'à 10 heures
  │
  └── Ticket de service
        └── Valide jusqu'à 600 minutes
```

La limitation de la durée de vie des tickets réduit la période pendant laquelle un ticket volé pourrait potentiellement être utilisé de manière abusive.

La tolérance de cinq minutes pour la synchronisation temporelle est également importante, car Kerberos utilise des timestamps pour se protéger contre les attaques par rejeu. Les membres du domaine doivent donc maintenir une synchronisation temporelle correcte avec le domaine.

Après avoir configuré la politique, nous avons appliqué les stratégies de groupe mises à jour :

```
gpupdate /force
```

Nous avons ensuite utilisé `klist` afin d'inspecter les tickets Kerberos délivrés au compte de test et avons confirmé que le domaine délivrait des tickets utilisant **AES-256-CTS-HMAC-SHA1-96**.

---

### Résultat

Avec ces trois politiques en place, NexGen dispose désormais d'une base d'authentification à l'échelle du domaine couvrant trois domaines complémentaires :

```
                Durcissement de l'authentification
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
      Politique de       Verrouillage       Politique
       mot de passe      des comptes         Kerberos
             │                │                │
             ▼                ▼                ▼
       Robustesse des    Protection contre   Durée de vie
       identifiants      le brute-force /    des tickets &
       & cycle de vie    password spraying   contrôles
                                            d'authentification
```

Ces contrôles ne remplacent pas les protections des identités mises en œuvre dans les étapes précédentes. Ils fournissent plutôt une couche de sécurité supplémentaire autour du processus d'authentification lui-même.

Combinés au **tiering Active Directory, aux restrictions d'ouverture de session administratives, à LAPS et aux gMSA**, ils contribuent à une approche de **défense en profondeur** pour la sécurité d'Active Directory.

---

## Conclusion

Ce lab a commencé par une question simple : **comment améliorer la sécurité d'un environnement Active Directory du point de vue de l'IAM ?**

Plutôt que de nous concentrer sur des paramètres de sécurité isolés, nous avons abordé le problème en identifiant les faiblesses liées à la manière dont les identités et les privilèges étaient gérés.

Le premier problème majeur concernait les **accès privilégiés**. L'environnement initial ne séparait pas suffisamment les privilèges administratifs, ce qui créait le risque qu'un administrateur compromis puisse se déplacer latéralement à travers l'infrastructure. Nous avons corrigé cela en mettant en œuvre un **modèle de tiering Active Directory**, séparant les comptes et les systèmes administratifs en différents niveaux de sécurité et en restreignant les endroits depuis lesquels chaque identité administrative pouvait s'authentifier.

Cependant, la séparation des privilèges ne suffisait pas. Nous avons ensuite identifié d'autres types d'identités privilégiées qui se trouvaient en dehors du périmètre du modèle de tiering.

Pour les **comptes de service**, nous avons migré le compte de service statique utilisé par l'application Web vers un **Group Managed Service Account (gMSA)**. Cette migration transfère la gestion du mot de passe des administrateurs humains vers Active Directory et introduit une génération et une rotation automatiques des mots de passe, réduisant ainsi considérablement les risques liés aux identifiants de service persistants.

Nous nous sommes ensuite intéressés aux **comptes administrateurs locaux**. Bien que les comptes administrateurs du domaine soient protégés par le modèle de tiering, les administrateurs locaux représentent toujours un privilège puissant sur les machines individuelles. **Windows LAPS** nous a permis de centraliser et d'automatiser la gestion de ces identifiants, notamment la génération, la rotation, le stockage et la récupération contrôlée des mots de passe. Nous avons également désactivé le compte Administrator intégré et introduit un compte administrateur personnalisé géré par LAPS.

Enfin, nous avons renforcé la couche d'**authentification du domaine** grâce aux politiques de mot de passe, de verrouillage des comptes et Kerberos. Ces contrôles ne constituent pas une défense principale contre toutes les attaques visant les identifiants, mais ils ajoutent une couche de protection supplémentaire contre les attaques par devinette, brute force, password spraying et contre une durée de vie excessive des tickets Kerberos.

Le modèle de sécurité obtenu peut être résumé ainsi :

```
                         Active Directory
                                │
             ┌──────────────────┼──────────────────┐
             │                  │                  │
             ▼                  ▼                  ▼
       Contrôle des        Gestion des        Durcissement
       accès privilégiés    identifiants      de l'authentification
             │                  │                  │
             ▼                  ▼                  ▼
          Tiering          gMSA + LAPS       Politique de mot de passe
       Deny Logon          + Hardening        Verrouillage des comptes
                                               Politique Kerberos
```

Plus important encore, chaque contrôle répond à une partie différente de la surface d'attaque liée aux identités :

|Problème de sécurité|Contrôle mis en œuvre|
|---|---|
|Privilèges administratifs excessifs|**Modèle de Tiering**|
|Déplacement latéral des administrateurs|**Politiques Deny Logon**|
|Mots de passe statiques des comptes de service|**gMSA**|
|Identifiants administrateurs locaux partagés|**Windows LAPS**|
|Compte Administrator intégré bien connu|**GPO de durcissement des comptes**|
|Attaques par devinette et brute force|**Politique de verrouillage des comptes**|
|Gestion insuffisamment robuste des mots de passe|**Politique de mot de passe**|
|Durée de vie excessive des tickets Kerberos|**Politique Kerberos**|

L'une des principales leçons de ce lab est que **la sécurité d'Active Directory ne s'obtient pas en déployant une technologie unique ou en activant simplement une liste de paramètres recommandés**.

Les contrôles de sécurité doivent être associés à des risques réels.

Par exemple, introduire une PKI simplement parce qu'elle est couramment présente dans les environnements d'entreprise n'améliorerait pas nécessairement cette architecture. Sans besoin concret d'authentification par certificat, de TLS interne, de cartes à puce ou d'un autre cas d'utilisation dépendant d'une PKI, son introduction ajouterait de la complexité opérationnelle sans répondre à une faiblesse identifiée.

C'est également pourquoi notre implémentation ne s'est pas limitée à la configuration des politiques. Nous avons régulièrement vérifié leur comportement réel : vérification des GPO effectivement appliquées, validation des tickets Kerberos, test des permissions de récupération des mots de passe LAPS, vérification du fonctionnement des gMSA et confirmation du respect des frontières administratives.

L'environnement obtenu n'est **pas invulnérable**. De nombreux aspects pourraient encore être étudiés dans un environnement de production, notamment la supervision et la détection, la sécurité des postes d'administration privilégiés, les chemins de délégation, AD CS si un besoin concret apparaît, la sécurité des sauvegardes, le durcissement des contrôleurs de domaine et la protection contre le vol d'identifiants.

Mais l'objectif de ce lab n'était pas de construire un environnement Active Directory « impossible à compromettre ».

L'objectif était de transformer un environnement initialement permissif en un environnement dans lequel **les privilèges sont séparés, les identifiants sont gérés, l'authentification est renforcée et les accès administratifs sont contrôlés de manière délibérée**.

C'est la base d'une architecture **Identity and Access Management (IAM)** plus mature.