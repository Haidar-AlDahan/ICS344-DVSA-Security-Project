# Lesson 4: Insecure Cloud Configurations

## 1. Goal and Vulnerability Summary

This lesson demonstrates an Insecure Cloud Configuration vulnerability caused by overly permissive S3 bucket permissions in DVSA. The components affected are the receipts S3 bucket and the Lambda function that processes uploaded files.

Because the bucket allows unauthorized uploads, an attacker can place arbitrary files into it. These files are later processed automatically by Lambda, allowing attacker-controlled input to reach backend logic.

This creates a serious security risk, as it may lead to unauthorized backend execution, data exposure, and abuse of cloud permissions.

## 2. Why This Works / Root Cause

The vulnerability exists because the receipts S3 bucket does not enforce strict least-privilege access.

The system assumes that any file inside the receipts bucket is legitimate and safe to process. However, if the bucket allows unauthorized or overly broad uploads, an attacker can place their own file into the same location used by the backend.

The root causes are:

- weak S3 bucket access control,
- disabled or incomplete public-access blocking,
- lack of strict bucket policy limiting uploads to trusted DVSA roles only,
- and backend processing that trusts files based only on their presence in the bucket.

## 3. Environment and Setup

Affected storage resources:

- DVSA-receipts-bucket

Affected Lambda function:

- DVSA-SEND-RECEIPT-EMAIL

Tools used:

- AWS Console
- S3 Console
- Lambda Console
- CloudWatch Logs
- AWS CLI or S3 upload interface
- Linux terminal

## 4. Reproduction Steps

Step 1 - Locate the receipts bucket

In the AWS Console, open S3 -> Buckets, which stores receipt files for the backend workflow.

Step 2 - Review insecure bucket configuration

Inside the receipts bucket permissions, insecure indicators were observed: Block all public access was off, ACLs were enabled, object ownership was not fully restricted, and CORS was permissive.

Before the fix, the CORS configuration allowed wildcard origins and dangerous methods such as PUT, POST, and DELETE.

```json
[
  {
    "AllowedHeaders": ["*"],
    "AllowedMethods": ["GET", "PUT", "POST", "DELETE", "HEAD"],
    "AllowedOrigins": ["*"],
    "ExposeHeaders": [],
    "MaxAgeSeconds": 3000
  }
]
```

Step 3 - Create a test file in CloudShell

```bash
echo "malicious test file" > evil.raw
ls -l evil.raw
```

Figure Creating the malicious test file evil.raw in CloudShell.

Step 4 - Upload the file directly to the receipts bucket

```bash
aws s3 cp evil.raw s3://dvsa-receipts-bucket-133789123225-us-east-1/evil.raw
aws s3 ls s3://dvsa-receipts-bucket-133789123225-us-east-1/
```

The object listing showed evil.raw in the bucket, proving that a manually created file entered backend storage.

Figure - Direct upload of evil.raw to the receipts bucket succeeded before the fix.

Figure - evil.raw is visible inside the receipts bucket after upload.

Step 5 - Check Lambda logs

```bash
aws logs describe-log-streams \
  --log-group-name "/aws/lambda/DVSA-SEND-RECEIPT-EMAIL" \
  --order-by LastEventTime \
  --descending \
  --max-items 5 \
  --region us-east-1
```

Figure - Lambda/CloudWatch log evidence showing backend processing/error activity after the upload.

## 5. Evidence and Proof

Evidence 1 - Insecure S3 configuration: the receipts bucket had weak configuration indicators. Block Public Access was off, CORS allowed wildcard origins, and CORS allowed PUT, POST, and DELETE.

Evidence 2 - Backend processing risk: the receipts bucket is connected to the DVSA receipt-processing workflow. Files uploaded into this bucket may be processed by DVSA-SEND-RECEIPT-EMAIL.

Evidence 3 - Successful manual upload: evil.raw

## 6. Fix Strategy / Probable Mitigation

The fix focused on hardening the S3 bucket configuration instead of changing frontend code.

The main mitigation strategy was to enable Block Public Access, remove wildcard public exposure, restrict CORS, remove dangerous CORS methods, restrict bucket policy access, and allow only trusted backend services to write receipt files.

## 7. Code / Config Changes

Change 1 - Enable Block Public Access

S3 -> dvsa-receipts-bucket-ACOUNT_ID-us-east-1 -> Permissions -> Block Public Access -> Edit -> Block all public access.

After the fix, the expected public access block configuration is:

```json
{
  "BlockPublicAcls": true,
  "IgnorePublicAcls": true,
  "BlockPublicPolicy": true,
  "RestrictPublicBuckets": true
}
```

Figure - Block Public Access enabled for the receipts bucket.

Change 2 - Harden CORS

The original CORS policy was too permissive because it allowed any origin and methods such as PUT, POST, and DELETE. The fixed CORS configuration removed wildcard exposure and restricted browser methods to safe access only.

```json
[
  {
    "AllowedHeaders": ["Authorization", "Content-Type"],
    "AllowedMethods": ["GET", "HEAD"],
    "AllowedOrigins": [
      "http://dvsa-website-new-ACOUNT_ID-us-east-1.s3-website.us-east-1.amazonaws.com"
    ],
    "ExposeHeaders": [],
    "MaxAgeSeconds": 3000
  }
]
```

Figure - CORS configuration restricted after removing wildcard public methods/origins.

Change 3 - Restrict the bucket policy

The bucket policy was updated so public or anonymous principals cannot write receipt objects. Write access should be limited to trusted DVSA backend roles and account-controlled identities only.

Figure - Bucket policy updated to enforce restricted access.

## 8. Verification After Fix

Because CloudShell was using the AWS root identity, a normal authenticated upload from CloudShell may still succeed. That is expected and does not prove public access is still open.

To properly test public upload access after the fix, the upload was repeated with --no-sign-request, which simulates an anonymous/public user.

```bash
echo "anonymous upload test" > public-test.raw
aws s3api put-object \
  --bucket dvsa-receipts-bucket-133789123225-us-east-1 \
  --key public-test.raw \
  --body public-test.raw \
  --no-sign-request \
  --region us-east-1
```

Expected and observed result:

```text
An error occurred (AccessDenied) when calling the PutObject operation: Access Denied
```

This confirms that public users can no longer upload files into the receipts bucket.

Figure Anonymous upload using --no-sign-request fails with AccessDenied after the fix.

## 9. Structured Operation and Security Analysis

| Vulnerability | Intended Rules(s) | Artifacts Used to Infer Rule | Normal Behavior Evidence | Exploit Behavior Evi dence |
| --- | --- | --- | --- | --- |
| Insecure Cloud Configuration - Lesson 4 | Only trusted DVSA backend services should place receipt files into the receipts S3 bucket. Public or unauthorized users must not upload files into backend storage. | S3 permissions page, Block Public Access setting, CORS configuration, S3 object listing, CloudShell upload result, CloudWatch logs. | The receipts bucket should only contain files generated by the DVSA backend receipt workflow. | A manually created file named evil.raw was uploaded directly into the receipts bucket and appeared in the S3 listing. |

| Vulnerability | Why this is a Deviation | Deviation Class | Fix Applied<br>(Where) | Post-Fix Verification | Optional Latency Before / After logging |
| --- | --- | --- | --- | --- | --- |
| Insecure Cloud Configuration - Lesson 4 | The bucket accepted direct manually uploaded content even though receipt storage should only receive trusted backend-generated files. This allows attacker-controlled input to enter a backend Lambda processing path. | Accidental misconfiguration with security-relevant abuse potential | S3 receipts bucket permissions were hardened by enabling Block Public Access, restricting CORS, and tightening the bucket policy. | Anonymous upload using --no-sign-request returned AccessDenied, proving public users can no longer upload to the bucket. | Not measured |

## 10. Takeaway / Lessons Learned

This lesson shows that weak cloud configuration can become a serious security issue. In DVSA, the receipts S3 bucket is part of the backend workflow, so allowing direct or public uploads could let attackers place files into a trusted processing path.

The main lesson is to apply least privilege to S3 buckets: block public access, restrict CORS, and allow uploads only from trusted backend services. Serverless applications must secure both the code and the cloud resources around it.
