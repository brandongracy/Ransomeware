# 🦠 Ransomware Simulation – Post-Exploitation Attack Scenario

## 📌 Overview
This project demonstrates a ransomware attack simulation conducted in a controlled and authorized lab environment.  
The objective was to replicate a real-world post-exploitation scenario, showing how an attacker can encrypt user data and impact business operations.

---

## 🎯 Objective
- Simulate a ransomware attack after gaining system access  
- Demonstrate the impact of data encryption  
- Highlight risks of weak security controls  
- Provide mitigation and defense strategies  

---

## نطاق Scope
- Environment: Controlled lab (authorized)  
- Target: Single compromised machine  
- Scenario: Post-exploitation attack  

---

## 🛠️ Tools Used
- Metasploit Framework  
- MsfVenom  
- Windows Command Line / PowerShell  
- Custom payload execution  

---

## 🔍 Initial Access
Access to the target machine was previously obtained through exploitation (e.g., SMB vulnerability / weak credentials).

---

## 💥 Attack Execution

### Step 1 – Payload Deployment
- Generated malicious payload using MsfVenom  
- Delivered payload to target machine  

### Step 2 – Execution
- Executed payload on compromised system  
- Established control over the machine  

### Step 3 – File Encryption Simulation
- Simulated encryption of user files  
- Targeted common directories (Documents, Desktop, etc.)  

---

## 🔐 Ransomware Behavior
- Files become inaccessible to the user  
- System remains operational but data is unusable  
- Demonstrates real-world ransomware impact  

---

## 💥 Impact
- Loss of access to critical files  
- Business disruption  
- Potential financial damage  
- Risk of data loss or exfiltration  

---

## 🛡️ Recommendations

1. Implement regular data backups (offline and secure)  
2. Apply least privilege principle  
3. Keep systems updated and patched  
4. Use endpoint protection / EDR solutions  
5. Monitor suspicious activity and file changes  
6. Disable unnecessary services  
7. Conduct security awareness training  

---

## ⚠️ Disclaimer
This project was conducted strictly in a controlled lab environment for educational and ethical purposes only.

---

## 📎 Full Report
See full detailed report here:  
👉 `ransomware-report.pdf`
