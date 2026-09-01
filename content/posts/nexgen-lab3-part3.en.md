---
title: "Active Directory Hardening: Identity, Credential & Authentication Protection (Part 3)"
date: 2026-09-01T00:00:00Z
draft: false
tags: ["Active Directory", "IAM", "Cybersecurity", "Windows LAPS", "gMSA", "Kerberos"]
summary: "A practical implementation of Active Directory hardening from an IAM perspective, covering administrative tiering, gMSA migration, Windows LAPS, and authentication policy hardening."
showToc: true
TocOpen: false
cover:
  image: "/images/nexgen-lab3-part3.en.png"
  relative: false
---

## Introduction

In [Part 2](https://ericyawilhit.netlify.app/posts/nexgen-lab3-part2/), we established boundaries and policies to contain administrative privileges. These controls allowed us to address several weaknesses identified during the auditing phase in [Part 1](https://ericyawilhit.netlify.app/posts/nexgen-lab3-part1/). But is our environment completely secure?

Although we have implemented several access controls, some important weaknesses remain:

- The Tiering Model protects privileged identities, but what about **service account identities**?
    
- Deny Logon restricts where administrative accounts can authenticate, but what about **local administrator accounts**?
    
- Administrative separation limits the impact of compromised accounts, but what happens if the credentials of those accounts themselves are compromised?
    
- Our authentication policies still need to provide adequate protection against **password-based attacks and authentication abuse**.
    

In other words, we have established **boundaries around administrative access**, but we have not yet fully addressed the **credentials and authentication mechanisms** behind that access.

This part will therefore focus on three complementary areas: **service account protection, local credential management, and authentication hardening**.

We will address these weaknesses through:

- **gMSA** to eliminate manually managed service account passwords;
    
- **Windows LAPS** to centrally manage local administrator credentials;
    
- **Password, Account Lockout, and Kerberos policies** to strengthen the domain's authentication baseline.

___

## Step 1 : Migrate the Web Application Service Account to a gMSA

The problem with our service account is that it uses static and non-expiring password. This increases the risk of credential compromise and makes the account vulnerable to attacks such as **Kerberoasting**.

To address this weakness, we will migrate the standard user account to a **Group Managed Service Account** (**gMSA**) is required. Here are the reasons of this choice :
- gMSA's password is managed by Active Directory, rather than by a human administrator
- gMSA's password is long and randomly generated, making offline password cracking significantly more difficult
- The password is never manually used and typed by a human
- The password is automatically rotated without human intervention

**How can we implement that ?** 
The migration requires several steps :
- The gMSA's password is generated and managed through the **Key Distribution Service (KDS)**, which relies on a **KDS Root Key**. Therefore, a KDS Root Key must be available in the domain.
- In order to retrieve the managed password, `NXG-SRV-APP01` must be authorized to use the gMSA. Instead of assigning this permission directly to the computer account, we created a dedicated security group, `GG-NXG-SRV-APP-gMSA-Hosts`, and granted the group permission to retrieve the gMSA's managed password.
- After creating the gMSA, it must be installed on the target server so that the server can use the managed account.
- Finally, we configured the IIS application pool to use `gmsa-nxg-webapp$` as its identity.

### Verification

![](/images/Pasted%20image%2020260830112035.png)

![](/images/Pasted%20image%2020260830113245.png)

![](/images/Pasted%20image%2020260830093958.png)

![](/images/Pasted%20image%2020260830095013.png)

We verified that:

- The gMSA was successfully created as an `msDS-GroupManagedServiceAccount`.
- `NXG-SRV-APP01` was authorized to retrieve its managed password.
- The gMSA was successfully installed on `NXG-SRV-APP01`.
- `Test-ADServiceAccount` returned `True`.
- The IIS application pool was configured to use `NEXGEN\gmsa-nxg-webapp$`.
- The HTTP SPNs were successfully associated with the gMSA, while the legacy service account no longer owns them.

At the end of the migration, password management is removed from humans and delegated to Active Directory. This significantly reduces the risk associated with static service account credentials and mitigates the Kerberoasting exposure identified during the initial audit.

___

## Step 2 : Protect Local Administrator Credentials with Windows LAPS

In our architecture, we've secured high-privilege domain accounts through the implementation of the **Tiering Model**. However, there are other privileged accounts that also require our attention: **local administrator accounts**.

These accounts have full administrative privileges on their respective machines, but there is currently no centralized credential management for them. Someone has to decide:

- What should each password be?
    
- Where should it be stored?
    
- When should it be changed?
    
- Who is allowed to retrieve it?
    
- How do we know who retrieved it?
    

Everything has to be manually managed by humans.

The solution here is to implement **Local Administrator Password Solution (LAPS)**.

**LAPS** is a Windows feature that automates the local administrator password lifecycle:

- The computer generates a new password.
    
- LAPS stores the password in Active Directory.
    
- The local Administrator password is changed.
    
- The password reaches its expiration time.
    
- LAPS generates another password.
    
- The process repeats.
    

Through LAPS, we can define policies governing the password lifecycle, including:

- How long and complex the generated password should be.
    
- How frequently the password should be rotated.
    
- Who is authorized to retrieve the stored password for a specific computer's local administrator account.
    

This removes manual password management from administrators and introduces a centralized, controlled, and auditable process for local privileged credentials.

### 1. Implement Windows LAPS

Windows LAPS provides two account-management modes:

- **Manual account management:** The IT administrator is responsible for creating and configuring the target local account. Windows LAPS only manages its password.
    
- **Automatic account management:** Windows LAPS manages the entire lifecycle of the target account. It can create a custom account, configure its properties, add it to the local Administrators group, enable or disable it, and automatically rotate its password.
    

For this lab, we'll use **Automatic Account Management** with a dedicated custom local administrator account. This allows us to keep the built-in Administrator account unused and disabled while giving us a separate, LAPS-managed account for emergency or administrative access.

#### 1.1 Prepare Active Directory

Before configuring Windows LAPS, we first need to extend the Active Directory schema with the attributes required to store LAPS-managed account information.

```powershell
Import-Module LAPS

Update-LapsADSchema
```

The schema only needs to be updated once for the domain.

Next, we need to delegate the required permissions.

Windows LAPS needs two different types of permissions:

1. **Computer self-permission** — allows computers to update their own LAPS information in Active Directory.
    
2. **Password retrieval permission** — determines which administrators are allowed to retrieve the stored passwords.
    

We first grant computers in our Tier 1 and Tier 2 OUs permission to update their own LAPS attributes:

```powershell
Set-LapsADComputerSelfPermission `
    -Identity "OU=Computers,OU=NexGen-Tier1,DC=nexgen,DC=lab"

Set-LapsADComputerSelfPermission `
    -Identity "OU=Computers,OU=NexGen-Tier2,DC=nexgen,DC=lab"
```

This creates the required separation between **writing** LAPS information and **reading** LAPS passwords.

#### 1.2 Control LAPS password retrieval

Password rotation alone is not sufficient. We also need to control who can retrieve the credentials stored in Active Directory.

Instead of granting password-read permissions directly to individual administrators, we'll use dedicated security groups:

```text
GG-NXG-T1-LAPS-Readers
GG-NXG-T2-LAPS-Readers
```

These groups will contain the administrative groups authorized to retrieve LAPS passwords for their respective tiers.

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

And for Tier 2:

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

We can then delegate the ability to retrieve LAPS passwords:

```powershell
Set-LapsADReadPasswordPermission `
    -Identity "OU=NexGen-Tier1,DC=nexgen,DC=lab" `
    -AllowedPrincipals @("NEXGEN\GG-NXG-T1-LAPS-Readers")

Set-LapsADReadPasswordPermission `
    -Identity "OU=NexGen-Tier2,DC=nexgen,DC=lab" `
    -AllowedPrincipals @("NEXGEN\GG-NXG-T2-LAPS-Readers")
```

This means that password retrieval is controlled independently from server administration.

For example, a Tier 1 administrator can administer a Tier 1 server without automatically receiving permission to retrieve every LAPS-managed password. Only members of the dedicated LAPS reader group receive that permission.

#### 1.3 Configure LAPS policies

LAPS policies will be applied to both **Tier 1 and Tier 2 computers**.

We'll therefore create two GPOs:

```text
Tier1-LAPS
Tier2-LAPS
```

![](/images/Pasted%20image%2020260830193629.png)

These policies configure the Windows LAPS client on computers belonging to their respective tiers.

Among other settings, we'll configure Windows LAPS to:

- use **Automatic Account Management**;
    
- create a dedicated custom local administrator account;
    
- add the account to the local Administrators group;
    
- generate a strong random password;
    
- automatically rotate the password;
    
- back up the password to Active Directory;
    
- control the account's enabled state according to our security requirements.
    
![](/images/Pasted%20image%2020260830192854.png)

The result is a local administrator account whose password lifecycle no longer depends on human administrators.

#### 1.4 Disable the built-in Administrator account

Although Windows LAPS can manage the built-in Administrator account, we deliberately choose to use a **separate custom account**.

The built-in Administrator account is therefore disabled through a separate GPO:

```text
Disabling Built-in Admin Account
```

This GPO is linked to both the Tier 1 and Tier 2 computer OUs.

The relevant policy is:

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

We set the policy to:

> **Disabled**

This gives us a clear separation between the two controls:

```text
Windows LAPS
    │
    ├── Creates custom local administrator
    ├── Generates password
    ├── Rotates password
    └── Stores password in AD

Local Account Hardening GPO
    │
    └── Disables built-in Administrator
```

After the policy is applied, we can verify the effective state on `NXG-SRV-APP01`:

```powershell
Get-LocalUser -Name "Administrator" |
    Select-Object Name, Enabled, PasswordLastSet
```

The expected result is:

```text
Name            Enabled
----            -------
Administrator   False
```

We can also verify that the corresponding GPO has been applied:

```powershell
gpresult /r /scope computer
```

![](/images/Pasted%20image%2020260901122220.png)

At this point, the built-in Administrator account is disabled, while our dedicated LAPS-managed administrator account remains available according to the configured LAPS policy.

### 2.5 Validate password retrieval

Finally, we need to validate not only that LAPS is managing the account, but also that our **authorization model** works as intended.

From an authorized Tier 1 administrator account, we can retrieve the password for a Tier 1 computer:

```powershell
Get-LapsADPassword -Identity "NXG-SRV-APP01" -AsPlainText
```

![](/images/Pasted%20image%2020260830224241.png)

The important point here is that the password is not simply "available in Active Directory." Access to it is controlled through the permissions we delegated earlier.

Our final model is therefore:

```text
                    Active Directory
                           │
              ┌────────────┴────────────┐
              │                         │
       Tier 1 Computers          Tier 2 Computers
              │                         │
              ▼                         ▼
        Windows LAPS              Windows LAPS
              │                         │
              ▼                         ▼
     Custom Local Admin       Custom Local Admin
              │                         │
              └────────────┬────────────┘
                           │
                    LAPS Password
                           │
                  ┌────────┴────────┐
                  │                 │
           T1 LAPS Readers   T2 LAPS Readers
```

With this implementation, we have addressed two different local-credential risks: the **manual management of local administrator passwords** and the continued use of the **well-known built-in Administrator account**.

___

## Step 3: Harden Authentication Policies

After securing service accounts and local administrator credentials, the next layer is to harden the authentication mechanisms used by domain users.

For this step, we will configure three domain-wide policies:

- **Password Policy**
    
- **Account Lockout Policy**
    
- **Kerberos Policy**
    

These policies will be configured in the **Default Domain Policy**, since they are intended to establish authentication requirements across the NexGen domain.

---

#### 3.1 Password Policy

The first layer is the password policy. Although password strength alone cannot provide complete protection against credential-based attacks, it remains an important layer of defense for human-managed accounts.

We configured the following settings:

|Policy|Configuration|
|---|--:|
|Enforce password history|**24 passwords**|
|Maximum password age|**42 days**|
|Minimum password age|**1 day**|
|Minimum password length|**14 characters**|
|Password must meet complexity requirements|**Enabled**|
|Store passwords using reversible encryption|**Disabled**|

The combination of password length, complexity requirements and password history makes password guessing and password reuse more difficult, while the maximum password age limits how long a compromised password can remain valid.

After configuring the policy, we forced a Group Policy update:

```powershell
gpupdate /force
```

We then verified the effective domain password policy:

```powershell
net accounts
```

The resulting configuration confirmed that the password policy was successfully applied:

```text
Minimum password age (days):                          1
Maximum password age (days):                          42
Minimum password length:                              14
Length of password history maintained:                24
```

---

#### 3.2 Account Lockout Policy

A strong password policy does not prevent an attacker from repeatedly attempting to authenticate against an account.

To mitigate brute-force and password-spraying attempts, we configured the **Account Lockout Policy**.

The following values were selected:

|Policy|Configuration|
|---|--:|
|Account lockout threshold|**5 invalid attempts**|
|Account lockout duration|**15 minutes**|
|Reset account lockout counter after|**15 minutes**|

This means that after five consecutive invalid authentication attempts, the account is temporarily locked for 15 minutes.

The observation window is also set to 15 minutes, meaning that the failed-attempt counter is reset after 15 minutes without reaching the lockout threshold.

The policy therefore provides protection against repeated authentication attempts while avoiding excessively long lockout periods.

However, account lockout must be configured carefully. An attacker could intentionally trigger account lockouts against legitimate users, turning the mechanism into a denial-of-service vector. For this reason, the values should be adapted to the organization's operational and security requirements.

After applying the policy:

```powershell
gpupdate /force
```

we verified the effective configuration:

```powershell
net accounts
```

The output confirmed:

```text
Lockout threshold:                                    5
Lockout duration (minutes):                           15
Lockout observation window (minutes):                15
```

---

#### 3.3 Kerberos Policy

The final component of our authentication hardening is the **Kerberos Policy**.

Kerberos is the primary authentication protocol used by Active Directory. While our previous configuration already uses modern Kerberos encryption such as AES-256, authentication security also depends on how long Kerberos tickets remain valid and how the KDC enforces authentication restrictions.

The following settings were configured:

|Kerberos Policy|Configuration|
|---|--:|
|Enforce user logon restrictions|**Enabled**|
|Maximum lifetime for service ticket|**600 minutes**|
|Maximum lifetime for user ticket|**10 hours**|
|Maximum lifetime for user ticket renewal|**7 days**|
|Maximum tolerance for computer clock synchronization|**5 minutes**|

These settings control the lifetime of Kerberos authentication tickets and the amount of time for which they can be renewed.

For example, a user's authentication flow can be represented as:

```text
User
  │
  │ Authentication
  ▼
KDC
  │
  ├── TGT
  │     └── Valid for up to 10 hours
  │
  └── Service Ticket
        └── Valid for up to 600 minutes
```

Limiting ticket lifetimes reduces the period during which a stolen ticket could potentially be abused.

The five-minute clock tolerance is also important because Kerberos relies on timestamps to protect against replay attacks. Domain members must therefore maintain accurate time synchronization with the domain.

After configuring the policy, we applied the updated Group Policy:

```powershell
gpupdate /force
```

We then used `klist` to inspect the Kerberos tickets issued to the test account and confirmed that the domain was issuing tickets using **AES-256-CTS-HMAC-SHA1-96**.

---

### Result

With these three policies in place, NexGen now has a domain-wide authentication baseline covering three complementary areas:

```text
                Authentication Hardening
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
 Password Policy   Account Lockout   Kerberos Policy
        │                │                │
        ▼                ▼                ▼
 Credential        Brute-force /      Ticket lifetime
 strength &        password spray     & authentication
 lifecycle         protection         controls
```

These controls do not replace the identity protections implemented in the previous steps. Instead, they provide an additional security layer around the authentication process itself.

Combined with **AD tiering, administrative logon restrictions, LAPS and gMSA**, they contribute to a defense-in-depth approach to Active Directory security.

___

## Conclusion

This lab started with a simple question: **how can we improve the security of an Active Directory environment from an IAM perspective?**

Rather than focusing on individual security settings, we approached the problem by identifying weaknesses in the way identities and privileges were managed.

The first major issue was **privileged access**. The initial environment did not sufficiently separate administrative privileges, creating the risk that a compromised administrator could move laterally across the infrastructure. We addressed this by implementing an **Active Directory Tiering Model**, separating administrative accounts and systems into different security tiers and restricting where each administrative identity could authenticate.

However, privilege separation alone was not enough. We then identified other types of privileged identities that were outside the scope of the tiering model.

For **service accounts**, we migrated the web application's static service account to a **Group Managed Service Account (gMSA)**. This transferred password management from human administrators to Active Directory and introduced automatic password generation and rotation, significantly reducing the risks associated with long-lived service account credentials.

We then addressed **local administrator accounts**. Although domain administrator accounts were protected by the tiering model, local administrators still represented a powerful privilege on individual machines. **Windows LAPS** provided centralized and automated management of these credentials, including password generation, rotation, storage and controlled retrieval. We also disabled the built-in Administrator account and introduced a dedicated LAPS-managed account.

Finally, we strengthened the domain's **authentication layer** through Password, Account Lockout and Kerberos policies. These controls do not constitute a primary defense against every credential-based attack, but they add another layer of protection against password guessing, brute-force attacks and excessive Kerberos ticket lifetimes.

The resulting security model can be summarized as:

```text
                         Active Directory
                                │
             ┌──────────────────┼──────────────────┐
             │                  │                  │
             ▼                  ▼                  ▼
        Privileged          Credentials       Authentication
        Access Control        Management          Hardening
             │                  │                  │
             ▼                  ▼                  ▼
          Tiering          gMSA + LAPS       Password Policy
        Deny Logon          + Account        Account Lockout
                         Hardening            Kerberos Policy
```

More importantly, each control addresses a different part of the identity attack surface:

|Security problem|Control implemented|
|---|---|
|Excessive administrative privileges|**Tiering Model**|
|Administrative lateral movement|**Deny Logon policies**|
|Static service account passwords|**gMSA**|
|Shared/local administrator credentials|**Windows LAPS**|
|Well-known built-in Administrator account|**Account Hardening GPO**|
|Password guessing and brute-force attacks|**Account Lockout Policy**|
|Weak password management|**Password Policy**|
|Excessive Kerberos ticket lifetime|**Kerberos Policy**|

One of the most important lessons from this lab is that **Active Directory security is not achieved by deploying a single technology or enabling a collection of recommended settings**.

Security controls have to be connected to actual risks.

For example, introducing PKI simply because it is commonly found in enterprise environments would not necessarily improve this particular architecture. Without a concrete requirement for certificate-based authentication, internal TLS, smart cards, or another PKI-dependent use case, introducing a PKI would add operational complexity without addressing an identified weakness.

This is also why the implementation did not stop at configuring policies. We repeatedly verified their actual behavior: checking effective Group Policies, validating Kerberos tickets, testing LAPS password retrieval permissions, verifying gMSA functionality and confirming that administrative boundaries behaved as expected.

The resulting environment is **not invulnerable**. There are still areas that could be investigated in a real production environment, such as monitoring and detection, privileged workstation security, delegation paths, AD CS if a concrete use case emerges, backup security, domain controller hardening, and protection against credential theft.

But the objective of this lab was not to build an "unhackable" Active Directory environment.

The objective was to transform an initially permissive identity environment into one where **privileges are separated, credentials are managed, authentication is hardened, and administrative access is deliberately controlled**.

That is the foundation of a more mature **Identity and Access Management architecture**.





