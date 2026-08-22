---
title: "Lab 3/5 (Part 1): The Emergency Active Directory Audit"
date: 2026-08-21
series: ["NexGen Solution Enterprise Security"]
tags: ["Active Directory", "Audit", "IAM", "Security Engineering"]
draft: false
description: "Addressing the security risks of an SSO federating an unhardened directory, this technical guide details an emergency Active Directory audit. Through a hands-on lab using Wazuh, PowerShell, and GPOs, discover how to quantify identity vulnerabilities (Kerberoasting, missing tiering, insecure service accounts) before remediating the source directory."
cover:
  image: /images/lab3-part1.en.png
  alt: Article Cover
  relative: false
---
## Scenario: The Illusion of Centralized Identity

At NexGen Solution, our previous milestones established a sovereign Single Sign-On baseline (Lab 1: Keycloak, FreeIPA, Gitea, Grafana) and deployed JIT access control over Nextcloud (Lab 2). Centralizing authentication gave us confidence—until a routine security event shattered our assumptions.

A minor Wazuh SIEM alert flagged abnormal behavior on a background service account (`svc-nexgen-webapp`). The investigation revealed a critical architectural flaw: **Keycloak was faithfully federating identities that were compromised at the source.** 

Our internal Active Directory (`nexgen.lab`) domain—powering corporate workstations and application servers—had never been hardened. Untracked admin accounts, active stale users, and a default 7-character password policy applied universally to accountants and Domain Admins alike. Keycloak trusted whatever AD provided, effectively hiding on-premises security debt behind a sleek SSO façade.

This writeup documents **Phase 1: The Emergency Audit**, quantifying our attack surface before engineering a fix.

---

## Environment Baseline

* **Domain Controller:** `NexGen-DC01` (`nexgen.lab`)
* **Target Systems:**
  * `NXG-WKS-FIN01` (Standard User Workstation - Finance/HR)
  * `NXG-ADM-IT01` (IT Admin Workstation)
  * `NXG-SRV-APP01` (Internal Application Server)
* **Auditing Tools:** PowerShell (`ActiveDirectory` module), `gpresult`, Local Group inspection.

---

## Audit Execution & Critical Findings

### Finding 1: Privileged Account Exposure & Missing Tiering
Running discovery on high-privilege groups showed that administrative power was centralized under a single default account, while local machine groups exposed domain credentials to lateral movement.

```powershell
# Checking critical domain groups
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName
Get-ADGroupMember -Identity "Enterprise Admins" | Select-Object Name, SamAccountName
Get-ADGroupMember -Identity "Schema Admins" | Select-Object Name, SamAccountName

# Checking local Administrators group across hosts
Get-LocalGroupMember -Group "Administrators"
````

- **Shared Domain Administrator:** Only the default `Administrator` account existed for domain management. Multiple IT staff sharing one account eliminates accountability and audit trails.
    
      
    
- **Privilege Creep on Workstations:** The `Domain Admins` group was present in the local `Administrators` group on standard workstations like `NXG-WKS-FIN01`.
    
      
    
- **The Risk:** If an attacker compromises a user on `NXG-WKS-FIN01` (e.g., via phishing), and a Domain Admin logs in to troubleshoot, the attacker can harvest Kerberos tickets or NTLM hashes from memory—gaining full Domain Dominance.
    
      
    

### Finding 2: Service Account Vulnerabilities (`svc-nexgen-webapp`)

Auditing Service Principal Names (SPNs) highlighted severe exposure on our web application service account.

```powershell
# Discovering accounts with registered SPNs
Get-ADUser -Filter {servicePrincipalName -like "*"} -Properties ServicePrincipalName | Select-Object Name, servicePrincipalName
```

![Pasted image 20260724163120](/images/Pasted%20image%2020260724163120.png)

#### 2.1 Applied Group Policies Audit

```powershell
# Executed from NXG-SRV-APP01
gpresult /h C:\rapport-gpo-nxg-srv-app01.html
```

![Pasted image 20260727104152](/images/Pasted%20image%2020260727104152.png)

![Pasted image 20260727104759](/images/Pasted%20image%2020260727104759.png)

- **Kerberoasting Exposure:** `svc-nexgen-webapp` holds SPN `HTTP/NXG-SRV-APP01`. Any authenticated user can request a Kerberos TGS ticket for this service and attempt offline password cracking.
    
      
    
- **Weak Password Policy:** The domain password policy enforced a minimum of only 7 characters.
    
      
    

#### 2.2 Password Expiration & gMSA Verification

```powershell
# Verifying Password Expiration
Get-ADUser -Identity "svc-nexgen-webapp" | Select-Object PasswordNeverExpires
```

![Pasted image 20260727105644](/images/Pasted%20image%2020260727105644.png)

```powershell
# Verifying gMSA Status
Get-ADServiceAccount -Identity "svc-nexgen-webapp"
```

![Pasted image 20260727110859](/images/Pasted%20image%2020260727110859.png)

  

- **Static Credentials & Interactive Logon:** `PasswordNeverExpires` was confirmed as `$true`. No password rotation existed and no GPOs restricted interactive logons (`Deny log on locally`).
    
      
    
- **gMSA Check:** Confirmed `svc-nexgen-webapp` is a standard user object created via `New-ADUser`, not a native Group Managed Service Account.
    
      
    

### Finding 3: Structural Debt & Default Container Misplacement

#### 3.1 Unmanaged Objects in Default Containers

```powershell
# Auditing default containers
Get-ADUser -Filter * -SearchBase "CN=Users,DC=nexgen,DC=lab" | Select-Object Name, DistinguishedName
Get-ADComputer -Filter * -SearchBase "CN=Computers,DC=nexgen,DC=lab" | Select-Object Name, DistinguishedName
```

![Pasted image 20260727234803](/images/Pasted%20image%2020260727234803.png)
  
- **Unmanaged Hosts:** All target machines resided in `CN=Computers`. Default container objects **cannot** have GPOs directly linked to them, rendering security policies unenforceable.
    

#### 3.2 Organizational Unit Hierarchy & Object Mixing


```powershell
# Inspecting AD OU Structure
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName
```

![Pasted image 20260802164045](/images/Pasted%20image%2020260802164045.png)


```powershell
# Inspecting Object Inventory under NexGen-Infrastructures
Get-ADObject -SearchBase "OU=NexGen-Infrastructures,DC=nexgen,DC=lab" -Filter 'ObjectClass -ne "organizationalUnit"'
```

![Pasted image 20260802165523](/images/Pasted%20image%2020260802165523.png)

- **Flat OUs & Unseparated Objects:** Departmental OUs stored `Users` and `Groups` together in a single directory without structural separation, making granular delegation and AGDLP group nesting impossible. 
    

## Baseline Audit Summary

| **Risk ID** | **Discovery Finding**                             | **Business & Technical Impact**                                         | **Target Remediation**                                                            |
| ----------- | ------------------------------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **SEC-01**  | `Domain Admins` in workstation local admin groups | Lateral movement & ticket harvesting leads to immediate domain takeover | Implement **Tier 0/1/2 Administrative Model** & User Rights Assignment GPOs       |
| **SEC-02**  | `svc-nexgen-webapp` has SPN + 7-char password     | Exposed to offline Kerberoasting and brute-force attacks                | Migrate to **gMSA** (240-char auto-rotated password) + Deny Interactive Logon GPO |
| **SEC-03**  | Hosts reside in default `CN=Computers` container  | Group Policy Enforcement is blocked across all endpoints                | Relocate hosts to dedicated Tiered OUs (`Tier1`, `Tier2`)[                        |
| **SEC-04**  | Flat OU layout & mixed Role/Resource groups       | Poor visibility, privilege sprawl, and complex access management        | Restructure OUs into sub-containers (`Users`, `Groups`) & enforce **AGDLP**       |

## Next Steps: Roadmap to Remediation

Proving that our identity source is insecure was step one. In **Lab 3 - Part 2**, we will begin full structural remediation by deploying administrative Tiering, isolating credentials, and moving hosts into managed OU boundaries.
