# ICS-344 Course Project: DVSA Vulnerability Discovery and Remediation

## Project Info
- **Course:** ICS-344 Information Security — Term 252
- **University:** King Fahd University of Petroleum and Minerals (KFUPM)
- **DVSA Website:** [redacted for submission]
- **AWS Region:** us-east-1

---

## What This Repository Contains
This repository documents the discovery, exploitation, fixing, and 
verification of security vulnerabilities in the OWASP Damn Vulnerable 
Serverless Application (DVSA), deployed on AWS.

---

## Repository Structure
Each lesson folder contains:
- A README.md with the full 10-part vulnerability report
- An exploit/ folder with reproduction scripts
- A fix/ folder with the patched code or config
- A screenshots/ folder with all evidence

---

## Lessons Completed

| # | Lesson | Status |
|---|--------|--------|
| 1 + 9 | Event Injection + Vulnerable Dependencies | ✅ Done |
| 2 | Broken Authentication | ✅ Done |
| 3 | Sensitive Information Disclosure | ✅ Done |
| 4 | Insecure Cloud Configuration | ⏳ Pending |
| 5 | Broken Access Control | ⏳ Pending |
| 6 | Denial of Service | ⏳ Pending |
| 7 | Over-Privileged Functions | ✅ Done |
| 8 | Logic Vulnerabilities | ✅ Done |
| 10 | Unhandled Exceptions | ✅ Done |

---

## Bonus Lessons Completed

| # | Lesson | Status |
|---|--------|--------|
| 1 | Billing Response Parsing Error | ✅ Done |
| 2 | SQL Injection | ✅ Done |


---

## Tools Used
- AWS Console (Lambda, CloudWatch, IAM, API Gateway)
- curl, python3, jq
- Browser DevTools (F12)
- VS Code

---

## Important Notice
DVSA is intentionally vulnerable and deployed only in a 
non-production AWS account strictly for educational purposes 
as part of ICS-344 at KFUPM.