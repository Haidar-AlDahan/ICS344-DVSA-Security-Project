# ICS344 DVSA Lesson 5 - Broken Access Control

## Overview

This folder documents Lesson 5, Broken Access Control, in the DVSA serverless application.

The vulnerable behavior allowed a normal user request sent to the public `/order` API to trigger administrative order-update behavior. The exploit used the event-injection behavior in `DVSA-ORDER-MANAGER` to invoke the privileged Lambda function `DVSA-ADMIN-UPDATE-ORDERS` and request an order status update.

## Vulnerability

The intended rule is:

```text
Only admin users should be able to perform administrative order updates.
```

In the vulnerable version, `DVSA-ADMIN-UPDATE-ORDERS` decoded the Cognito token and extracted the username, but it did not verify that the user was an administrator before reading:

```python
action = event["body"]["action"]
orderId = event["body"]["order-id"]
item = event["body"]["item"]
```

As a result, a normal authenticated user could indirectly reach admin-only behavior and update an order status.

## Exploit Summary

The exploit path was:

```text
Normal user token
-> POST /dvsa/order
-> injected node-serialize function executes in DVSA-ORDER-MANAGER
-> backend invokes DVSA-ADMIN-UPDATE-ORDERS
-> order update is attempted
```

The PowerShell script in this folder demonstrates the payload format used in the lab. It uses placeholders for the access token so no credential is committed.

## Fix Strategy

The Lesson 5 fix is applied inside:

```text
DVSA-ADMIN-UPDATE-ORDERS / admin_update_orders.py
```

The fix adds an authorization check immediately after the token is decoded and the username is extracted. Normal users are rejected before the function reads `action`, `order-id`, or `item`.

```python
if token.get("custom:is_admin") != "true":
    return {
        "status": "err",
        "msg": "Unauthorized",
        "statusCode": 403
    }
```

This fix is intentionally scoped to Lesson 5. Event injection is covered in Lesson 1, vulnerable dependencies are covered in Lesson 9, and IAM least privilege is covered in Lesson 7.

## Verification

After deploying the fix, the same PowerShell payload was repeated using a normal user token.

Observed result:

```json
{"status":"err","msg":"unknown action"}
```

The order list was checked before and after the attempt, and the target order status remained unchanged. This confirmed that the Lesson 5 exploit path no longer updated the order.

## Files

| File | Purpose |
|---|---|
| `admin_update_orders_fixed.py` | Fixed Lambda code with the admin authorization check. |
| `lesson5_exploit.ps1` | PowerShell exploit/verification payload with placeholders. |
| `lesson5_fix_summary.json` | Structured summary of the fix and verification result. |

## Screenshot Checklist

Add screenshots for:

1. Orders before the verification attempt.
2. The PowerShell exploit payload being rerun.
3. The error response after the fix.
4. Orders after the verification attempt showing the status did not change.
5. The code fix in `admin_update_orders.py`.
