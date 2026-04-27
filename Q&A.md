**1. What is OWASP Top 10 ?**
```
OWASP Top 10 is a list of the most critical web application security risks. It is created by OWASP to help developers and security professionals understand the most common and dangerous vulnerabilities.
   The List of web OWASP top 10 2025 are:
   - A01 Broken Access Control
   - A02	Security Misconfiguration
   - A03	Software Supply Chain Failures
   - A04	Cryptographic Failures
   - A05	Injection
   - A06	Insecure Design
   - A07	Authentication Failures
   - A08	Software or Data Integrity Failures
   - A09	Security Logging & Alerting Failures
   - A10	Mishandling of Exceptional Conditions
```
**2. Which Is the Newest Category Added in OWASP top 10 2025**
```
When compared to the OWASP Top 10 2021, the newest category in the OWASP Top 10 2025 is A10: Mishandling of Exceptional Conditions.
```
**3. What is Mishandling of Exceptional Conditions? (do prepration same for others category)**
```

```
**4. What is IDOR**
**5. What are the common ways to check the IDOR vulnerability**
**6. What is the Impact/Highest Impact of IDOR vulnerability**
**7. What are Proper Mitigation/Remediation for IDOR Vulnerability**
### Scenario-Based Questions
```
1. A web application uses the following URL to show user profiles: https://app.com/profile?id=101
   If a user changes the ID to 102 and can see another user’s profile

2. An API request is used to update user details:
   {
     "user_id": 101,
     "email": "user@example.com"
   }
   If an attacker changes user_id to 102 and successfully updates another user’s email:

👉 Question: What vulnerability is this?
             Is this horizontal or vertical privilege escalation? Why?

3. A website allows users to download invoices: https://shop.com/invoice/1001.pdf
   An attacker changes it to 1002.pdf and downloads another user’s invoice:

👉 Question: What kind of data exposure is happening?
             What type of IDOR is this?
             What control is missing on the server?

4. A normal user accesses: https://app.com/admin/user?id=1
   And is able to view and modify admin details:

👉 Question: What type of privilege escalation is this?

5. A website stores user info in cookies: user_id=101
   An attacker changes it to 102 and gains access to another account:

👉 Question: What vulnerability is this?
             Why is this dangerous?

```
