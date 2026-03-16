# Entra ID Security & Detection Lab

This repository contains Splunk queries, notes, and investigation work from the **TryHackMe Entra ID Security & Detection room**.  
It demonstrates how to detect, investigate, and respond to credential-based attacks in Microsoft Entra ID.

---

## 🔑 Skills Covered
- **Sign-in Log Analysis**  
  - Differentiating brute force vs. password spray using error codes and distinct user counts.  
  - Pivoting by IP addresses to identify attacker infrastructure.

- **Conditional Access & Identity Protection**  
  - Investigating appliedConditionalAccessPolicies results (`success`, `failure`, `notApplied`).  
  - Detecting risk signals like *impossible travel*, *anonymized IPs*, and *unfamiliar sign-in properties*.

- **MFA & Bypass Techniques**  
  - Spotting MFA fatigue (prompt bombing) via repeated error codes (`50074`, `50076`, `500121`).  
  - Recognizing SIM swapping and Adversary-in-the-Middle (AiTM) phishing in logs.

- **Privilege Escalation & Persistence**  
  - Detecting suspicious role assignments (e.g., Global Admin elevation).  
  - Spotting backdoor account creation and alternate MFA registrations.

- **OAuth Application Abuse**  
  - Identifying consent grants to malicious applications.  
  - Distinguishing delegated vs. application permissions.  
  - Flagging high-risk scopes like `Mail.Read.All`, `Files.ReadWrite.All`, and `offline_access`.

---

## 📂 Repository Structure
- `queries/` → Splunk queries for each detection scenario  
- `notes/` → Challenges, work-arounds, and investigation journal  
- `README.md` → Overview of the lab and skills learned  

---

## 📊 Example Queries

### Sign-in Detection
```spl
index="task-1" sourcetype="azure:aad:signin"
| where status.errorCode!=0
| stats count by userPrincipalName, ipAddress, status.errorCode
| sort - count
