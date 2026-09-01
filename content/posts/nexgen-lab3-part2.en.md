---
title: "Hardening Active Directory: Enterprise Access Model & Administrative Tiering (Part 2)"
date: 2026-08-24T23:24:00Z
draft: false
tags: ["Active Directory", "IAM", "Cybersecurity", "GPO", "Windows Server"]
categories: ["Cybersecurity", "Homelab"]
summary: "Implementing Microsoft's Enterprise Access Model in Active Directory through OU restructuring, administrative privilege delegation, and Deny Logon GPO enforcement."
showToc: true
TocOpen: false
cover:
  image: "/images/nexgen-lab3-part2.en.png"
  relative: false
---

## Introduction
In Part 1, we audited the domain and discovered several critical vulnerabilities: Domain Admin credentials present on a standard workstation, non-gMSA service accounts, a flat OU structure, and hosts residing in the default `Computers` container.

In this lab, we will address these vulnerabilities by implementing Microsoft's Enterprise Access Model. The goal is to isolate administrative privileges, systems, and credentials into distinct security boundaries based on risk and criticality. The core principle is simple: **never expose high-privilege account credentials on lower-risk or standard computers**, ensuring that if a standard endpoint is compromised, attackers cannot harvest high-privilege credentials from memory.

The implementation follows 4 main steps:

---

## Step 1: OU Restructuring
From a security perspective, an Organizational Unit's (OU) primary role is not to reflect the corporate organizational chart, but to model security boundaries. Grouping objects of equal criticality into dedicated OUs allows us to apply tailored Group Policy Objects (GPOs) and delegation rules. 

Below is the structure we will implement:

```text
DC=nexgen,DC=lab
├── OU=NexGen-Tier0
│   ├── OU=Admin-Accounts
│   ├── OU=Admin-Groups
│   ├── OU=Service-Accounts
│   └── OU=Computers (Domain Controllers)
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
            └── ... (HR, Finance, R&D, Sales)
````

### Administrative Rules

- **Tier Isolation:** Each Tier will have dedicated administrative accounts assigned strictly to manage its scope.
    
      
    
- **Account Separation:** Administrators will maintain separate accounts: a standard account for daily tasks (e.g., email, web browsing) and dedicated administrative accounts for each Tier they manage.
    
      
    
- **User Categorization:** All standard user accounts will be allocated under `Standard-Users` organized by department. Within each department, objects are classified by object type (user accounts in `Users`, security groups in `Groups`).
    
      
    

The script for this step can be found [here](https://github.com/Brizman236/Home-Labs/blob/main/02-Identity-Access-Management/02-NexGen-IAM-Infrastructure/Ressources/Scripts/Phase2-Step1.ps1).

  

## Step 2: Privilege Separation & Delegation

A major vulnerability in default Active Directory installations is reliance on a single, full-privilege `Domain Admin` or built-in `Administrator` account. Because this account is heavily targeted in cyberattacks, compromising it results in complete domain takeover.

  

To reduce the attack surface, we restrict the daily use of Domain Admin accounts through three key controls:

  

1. **Creating Dedicated Tier Accounts:** Provisioning explicit admin accounts for each Tier (e.g., `adm-user-t0`, `adm-user-t1`, `adm-user-t2`).
    
      
    
2. **Creating Tier Security Groups:** Establishing administrative groups (`GG-T0-Admins`, `GG-T1-Admins`, and `GG-T2-Admins`).
    
      
    
3. **Delegating Administrative Permissions:** Assigning granular rights directly to Tier groups without adding them to built-in high-privilege groups like `Domain Admins` or `Enterprise Admins`, adhering to the Principle of Least Privilege (PoLP).
    
      
    

### Permission Delegation Breakdown

- **Tier 0 (Identity & Control Plane):** Tier 0 administrators manage Domain Controllers, PKI, and Identity Providers. Because these components control identity across the entire domain, Tier 0 admins require full control over domain objects and reside in the `Domain Admins` group.
    
      
    
- **Tier 1 (Servers & Applications):** Server administrators need to deploy databases, web applications (e.g., Gitea, Nextcloud), and line-of-business servers without requiring domain-wide authority. They are delegated rights only to create/manage Computer objects in `OU=NexGen-Tier1`, manage Group Managed Service Accounts (gMSAs), and control Tier 1 local administrator groups.
    
      
    
- **Tier 2 (Endpoints & Helpdesk):** Helpdesk personnel support end-users and troubleshoot endpoints. They are granted permissions solely to reset end-user passwords, unlock user accounts, and join workstations to `OU=NexGen-Tier2`.
    
      
    

The script for this step can be found [here](https://github.com/Brizman236/Home-Labs/blob/main/02-Identity-Access-Management/02-NexGen-IAM-Infrastructure/Ressources/Scripts/Phase2-Step2.ps1).

  

## Step 3: Deny Logon GPO Enforcement

With administrative accounts created, we enforce restrictions to prevent Tier Administrators from authenticating to unauthorized Computer Tiers, blocking lateral movement and credential harvesting.

  

### GPO Configuration

1. Open **Group Policy Management** (`gpmc.msc`).
    
      
    
2. Under **Group Policy Objects**, create 3 GPOs: `Tier0-DenyLogon`, `Tier1-DenyLogon`, and `Tier2-DenyLogon`.
    
      
    
3. For each policy, configure the following **User Rights Assignments** under:
    
    `Computer Configuration` > `Policies` > `Windows Settings` > `Security Settings` > `Local Policies` > `User Rights Assignment`:
    
      
    - **Deny log on locally** (`SeDenyInteractiveLogonRight`)
        
          
        
    - **Deny log on through Remote Desktop Services** (`SeDenyRemoteInteractiveLogonRight`)
        
          
        
    - **Deny log on as a batch job** (`SeDenyBatchLogonRight`)
        
          
        
    - **Deny log on as a service** (`SeDenyServiceLogonRight`)
        
          
        
4. Populate each policy with the security groups from other tiers. For example, inside `Tier0-DenyLogon`, add `GG-T1-Admins` and `GG-T2-Admins` to the deny lists.
    
      
    
5. Link each GPO to its target OU (e.g., link `Tier0-DenyLogon` to `OU=NexGen-Tier0` and the built-in `Domain Controllers` OU).
    
      
    

## Verification

Before applying the policies, a Tier 1 administrator account (`adm-eyawil-t1`) can successfully authenticate and log on to Tier 2 computer `NXG-WKS-FIN01`:

<video width="100%" controls>
  <source src="/videos/before-denygpo.mp4" type="video/mp4">
  Votre navigateur ne supporte pas la lecture de cette vidéo.
</video>


After linking the `Tier0-DenyLogon` GPO and running `gpupdate /force`, logon attempts by `adm-eyawil-t1` to the Domain Controller are explicitly denied:

![](/images/Pasted%20image%2020260824223753.png)


<video width="100%" controls>
  <source src="/videos/after-denygpo.mp4" type="video/mp4">
  Votre navigateur ne supporte pas la lecture de cette vidéo.
</video>


## Next Steps & Future Enhancements

While OU restructuring and Deny Logon GPOs drastically reduce credential exposure, securing Active Directory is an iterative process. In **Part 3**, we will build upon this tiering foundation with the following enterprise controls:

  

1. **Deploying Group Managed Service Accounts (gMSAs):**
    
      
    - Migrate vulnerable interactive service accounts to gMSAs to enforce automatic password rotation and restrict execution strictly to designated host SPNs.
        
          
        
2. **Implementing Windows LAPS:**
    
      
    - Deploy LAPS across all Tier 1 servers and Tier 2 workstations to randomize local `Administrator` passwords, eliminating lateral movement via shared local credentials.
        