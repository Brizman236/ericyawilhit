---
title: "Securing File Sharing: Implementing RBAC and JIT Provisioning with Keycloak and Nextcloud"
date: 2026-06-05
draft: false
description: "Discover how to implement tight, automated role-based access control (RBAC). This hands-on guide walks through interconnecting Keycloak and Nextcloud via the Social Login app, passing the 'groups' claim, and Just-In-Time (JIT) provisioning to dynamically partition team folders."
summary: "Hands-on guide to setting up RBAC and Just-In-Time (JIT) Provisioning between Keycloak and Nextcloud to secure company data."
categories:
  - Cybersecurity
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
  alt: "Nextcloud interface showing team folders partitioned by group"
  relative: false
---
 
 
## Context & Objective 
 
### Current situation
 
In **Lab 1**, we laid the groundwork for our infrastructure by implementing single sign-on for our applications (Gitea and Grafana). However, a new challenge arises with the introduction of collaborative applications.
 
### The business problem
 
NexGen's leadership is rolling out **Nextcloud** for file sharing. However, letting every employee access every document violates the principle of least privilege — a developer shouldn't have access to the salary grid for all employees in the company.
HR data must not be visible to technical teams, and vice versa.
 
### Lab 2 objective
 
Evolve the existing infrastructure to implement role-based access control (**RBAC**). Access to Nextcloud folders must be automatically restricted and provisioned on the fly based on the user's department, with no local permission management.
To do this, we're going to create two user groups, **HR** and **Devs**.
 
___
 
## Step 1: Evolving the Directory
 
In this step we'll enrich the source of truth set up previously by creating:
- the `dev-empl` and `hr-empl` groups
- the `bob` and `alice` users, who will be assigned to their respective groups
```sh
# Create the groups
ipa group-add dev-empl --desc="Developers department"
ipa group-add hr-empl --desc="Human Resources department"
 
# Create the users
ipa user-add alice --first='Alice' --last='Dupont' --email='alice@nexgen.lab' --city "Dakar" --state='Sénégal' --orgunit='RH' --title='Responsable RH'
echo 'Azerty123' | ipa user-mod alice --password
 
ipa user-add bob --first='Bob' --last='Jackson' --email='bob@nexgen.lab' --city "Dakar" --state='Sénégal' --orgunit='Devs' --title='Développeur Web Senior'
echo 'Azerty123' | ipa user-mod alice --password
 
# Add the users to their group
ipa group-add-member hr-empl --users=alice
ipa group-add-member dev-empl --users=bob
```
 
With the groups created and users assigned to them, let's move on to step 2.
___
 
## Step 2: Extracting and Passing Roles
 
For Nextcloud to be able to apply **RBAC**, it first needs to know the role — the group the user belongs to. However, it doesn't have its own database of domain users. **So who provides the users? The identities.**
**Keycloak.** Thanks to OpenID Connect, Nextcloud will **delegate** user authentication to Keycloak, which will send back the user's information via a **JWT** token. By default, however, the token doesn't contain the user's domain group(s).
 
In this step, we'll add this information by:
- Creating a dedicated **Client Scope**: a **Client Scope** is a security mechanism that defines which categories of information a client/SP is allowed to request from Keycloak. The Client Scope we're going to create will let Nextcloud request the groups the user belongs to.
- Configuring a **Mapper** for this **Client Scope**: the Mapper's role is to define which information gets provided — in our case, the user's groups.
### Step 2.1: Creating the Client Scope
 
- In the left-hand menu, click **Client Scopes**
- On the page, click **Create a client scope**
- Fill in the form:
	- **Name**: `user-group`
	- **Description**: `NexGen scope for passing FreeIPA groups to client applications`
	- **Type**: `Default`
	- **Protocol**: `OpenID Connect`
	- Check **Include in Token Scope**
	- Click **Save**
	![Pasted image 20260603221010](/images/Pasted%20image%2020260603221010.png)
	
### Step 2.2: Configuring the Mapper
- On the created Client Scope's page, click the **Mappers** tab
- Click **Configure a new mapper**
- From the list, select **Group Membership**
- Configure the settings as follows:
	- Name: **group-mapper**
	- Token Claim Name: **groups** — this is the exact name of the JSON key that will appear in the **JWT**
	- Uncheck **Full group path** so that Keycloak only sends the group name (e.g. `hr-empl`) and not the full path (`\hr-empl`)
	- Click **Save**
	![Pasted image 20260603222051](/images/Pasted%20image%2020260603222051.png)
___
## Step 3: Creating and Integrating the Nextcloud Client/SP
 
In this step we're going to configure Nextcloud so it can support OIDC authentication.
 
> Nextcloud doesn't natively support this, which is why the `Social Login` app needs to be installed.
 
#### Step 3.1: Creating the client 
 
- In the left-hand menu, **click** **Clients**
- On the Clients page, **click** the **Create client** button
- Fill in the settings:
	- **General Settings**
		- **Client type**: `OpenID Connect`
		- **Client ID**: `nextcloud`
		- **Name**: `NextCloud`
		- Click **Next**
	- **Capability config**
		- Check **Client authentication**
		- Check only **Standard Flow** in the **Authorization flow** section
		- Click **Next**
	- **Login settings**
		- **Root URL**: `https://nextcloud.nexgen.lab/`
		- **Valid redirect URIs**: `https://nextcloud.nexgen.lab/*`
		- **Valid post logout redirect URIs**: `https://nextcloud.nexgen.lab/`
		- **Web origins**: `https://nextcloud.nexgen.lab/`
		- Click **Save**
After creating the client, we should copy its secret.
 
### Step 3.2: Integrating the Nextcloud Client
 
In this step we're going to integrate OIDC authentication into Nextcloud and configure it to use **Keycloak** as its **Identity Provider**.
 
> NB: You need to be logged in as admin
 
- **Click** the profile icon, then **Administration settings**
- In the left-hand menu, under the **Administration** section, **click** **Social login**
	- Make sure only the options below are checked:
		- **Prevent creating an account if the email address exists in another account**: prevents duplicate accounts by blocking account creation if another user already has the same email address
		- **Update user profile every login**: allows the profile to be updated on every login. This supports centralized revocation — when access is revoked or a role removed, Nextcloud syncs the information the next time the user logs in.
		- **Automatically create groups if they do not exist**: supports centralization, since if a user is added to a brand-new group and then logs into the application, the group is automatically created there.
	- **Click** **Custom OpenID Connect**
		- **Internal name**: `keycloak`
		- **Title**: `KeyCloak`
		- **Authorize url**: `https://sso.nexgen.lab/realms/master/protocol/openid-connect/auth`
		- **Token url**: `https://sso.nexgen.lab/realms/master/protocol/openid-connect/token`
		- **User info url**: `https://sso.nexgen.lab/realms/master/protocol/openid-connect/userinfo`
		- **Logout url**: `https://sso.nexgen.lab/realms/master/protocol/openid-connect/logout`
		- **Client Id**: `nextcloud`
		- **Client Secret**: the copied secret
		- **Scope**: `openid`
		- **Groups claim**: `groups`
		- **Button style**: `KeyCloak`
		- **Default group**: `None`
		- Click **Save**
### Step 3.3: Logging Users into Nextcloud
 
Now that SSO is configured on Nextcloud, we're going to log in with our two users, `alice` and `bob`.
 
<video width="100%" controls>
  <source src="/videos/sso-nextcloud.webm" type="video/webm">
  Your browser does not support playing this video.
</video>
If we log in as an administrator and go to **Accounts**, we'll notice that the users' groups were **automatically** created in Nextcloud with the `keycloak` prefix:
 
![Pasted image 20260605232824](/images/Pasted%20image%2020260605232824.png)
 
With the users logged in and the groups created, we can now move on to creating the shared folders with their access rights.
 
____
 
## Step 4: Creating Team Folders
 
In this step we're going to create two **Team Folders**, one for the **HR** team and one for the **Devs** team, and then check whether the access rights actually work.
 
> NB: The **Team Folder** app must be installed
 
### Step 4.1: Creating the HR Folder
 
- Log in as admin, then go to **Administration settings**
- In the left-hand menu, click **Team Folder**
- Create the **NEXGEN-RH** folder and fill in the settings as follows:
	- Group or Team: `keycloak-hr-empl` — here we're assigning this folder to the HR group. Check the following rights: **Read**, **Write**, **Delete**, **Share**.
	- Check **Advanced Permissions**, then select **Alice Dupont** as the user who will manage this folder. **Alice** will be able to allow or deny specific actions in this folder for any user in the group that has access to it.
### Step 4.2: Creating the Developers Folder
 
- Log in as admin, then go to **Administration settings**
- In the left-hand menu, click **Team Folder**
- Create the **NEXGEN-DEV** folder and fill in the settings as follows:
	- Group or Team: `keycloak-dev-empl` — here we're assigning this folder to the HR group. Check the following rights: **Read**, **Write**, **Delete**, **Share**.
	- Check **Advanced Permissions**, then select **Bob Jackson** as the user who will manage this folder.
> With Nextcloud you can go further by choosing a specific group of users who will be able to administer the folder.
___
 
### Step 4.3: Verification
 
We're going to verify our folder configurations — we expect that only users in the `hr-empl` group (the HR team) will be able to access their folder, and likewise for those in the `dev-empl` group (the dev team).
 
We'll log in to **Bob**'s and **Alice**'s accounts and check which folder each one has access to.
 
<video width="100%" controls>
  <source src="/videos/rbac-test.webm" type="video/webm">
  Your browser does not support playing this video.
</video>
We can see that our configurations have been validated ✅.
 
___
 
## Step 5: Validation Scenario – A New Employee Joins (Lifecycle & JIT)
 
To prove the **effectiveness** and **robustness** of this architecture, we're going to simulate a real business scenario: **a new employee joining the Human Resources department**.
 
The goal is to demonstrate the concept of a **Single Source of Truth** and **Just-In-Time (JIT) Provisioning**: the system administrator creates the user **only once** (in the central FreeIPA directory). After that, the employee logs in and instantly gets access to their tools and team folders, with no human intervention on Nextcloud whatsoever.
 
The video below shows:
- Creating the user in FreeIPA and adding them to the global Human Resources group `hr-empl`
- Keycloak picking up the user through federation
- The user's first login via SSO on Nextcloud, where their account is automatically created and added to the HR group
- Direct access to the **NEXGEN-RH** folder
- The Nextcloud user list being updated
<video width="100%" controls>
  <source src="/videos/scenar-valid.webm" type="video/webm">
  Your browser does not support playing this video.
</video>
 
___
 
## Lab 2 Conclusion: A Sovereign, Agile, and Secure IAM Model
 
This second deliverable successfully validates the implementation of fine-grained, dynamic access management within the **NexGen** infrastructure. By moving from simple centralized authentication to end-to-end role-based access control (RBAC), we solved a major challenge: **reconciling the confidentiality of sensitive data with the automation of identity engineering processes.**
 
### 📈 What This Lab Demonstrates (Technical Takeaways)
 
The deployed architecture rests on three fundamental pillars of modern security infrastructure:
 
1. **The principle of least privilege upheld:** The absolute separation between the `NEXGEN-RH` and `NEXGEN-DEV` team folders proves that partitioning confidential data (such as salaries or technical specifications) is now an inviolable technical reality.
2. **Just-In-Time (JIT) Provisioning as the standard:** The demonstration of a new hire joining illustrates the complete disappearance of redundant administrative tasks. Local application accounts no longer need to be manually provisioned by an administrator; they're created and configured at the exact moment the user initiates their first login.
3. **A single source of truth:** Whether it's a new hire, a department transfer, or a change in rights, **the FreeIPA directory remains the one and only point of control**. Keycloak takes care of dynamically propagating these changes to the application ecosystem via the JWT token's claims, eliminating the major risk of "ghost accounts" or orphaned access.
By completing this Lab 2, NexGen now has a modern, fully centralized, highly auditable collaborative platform aligned with identity governance (IAM) best practices.