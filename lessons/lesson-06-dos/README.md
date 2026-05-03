# Lesson 6: Denial of Service (DoS)

## 1. Goal and Vulnerability Summary

This lesson demonstrates a Denial-of-Service vulnerability in the DVSA billing workflow. The affected components are API Gateway, DVSA-ORDER-BILLING, and DVSA-PAYMENT-PROCESSOR. The billing and payment path has limited concurrent processing capacity, so repeated parallel billing requests can consume that shared capacity. During the test, legitimate users were unable to complete payment and received 500/502 failures. The main weakness is missing fair-use protection around an expensive backend workflow.

## 2. Why This Works / Root Cause

The vulnerability works because repeated billing requests are allowed to reach the payment-processing path without strong per-user throttling, or request shaping. The payment processor behaves like a slow external service, so concurrent requests remain in flight for several seconds. When enough requests are sent in parallel, the limited Lambda/payment capacity is consumed, Lambda throttles increase, and unrelated billing requests fail with gateway or server errors.

## 3. Environment and Setup

AWS Region: us-east-1.

Affected API path: POST /dvsa/order with action=billing.

Affected functions: DVSA-ORDER-BILLING and DVSA-PAYMENT-PROCESSOR.

Tools used: browser DevTools Network tab, curl, jq, bounded bash request script, and AWS Lambda/CloudWatch metrics.

Test data: a fresh unpaid order and test payment card 4242424242424242 with a normal authenticated user token.

## 4. Reproduction Steps

Step 1 - Open DVSA and log in as a normal authenticated user.

Step 2 - Open DevTools, then Network, then Fetch/XHR, and capture the POST /dvsa/order request plus the Authorization token.

Step 3 - Create a fresh unpaid order so the billing action can be tested against a valid order-id.

Step 4 - Send one normal billing request with curl and confirm it succeeds with status ok and a payment token.

Step 5 - Run the bounded lesson6_dos_test.sh script to send repeated concurrent billing requests against the same protected billing endpoint.

Step 6 - Watch the script output for HTTP status codes and response bodies while requests are still in flight.

Step 7 - During the request flood, submit another normal order/billing request from the browser as a second user or fresh session.

Step 8 - Observe that the legitimate browser request receives 502 Bad Gateway during the DoS window.

Step 9 - Open Lambda metrics for DVSA-ORDER-BILLING and capture invocations, duration, errors, throttles, and concurrent executions.

## 5. Evidence and Proof

Screenshot 1 - A normal billing request succeeds before the DoS test.

The baseline request returned status ok, amount 72, and a payment token, proving the billing workflow worked normally before the load test.

Screenshot 2 - The bounded request flood caused backend failures during billing.

The stress output shows many HTTP 500 and 502 responses, with some duplicate-order responses, indicating the billing/payment path was overloaded.

Screenshot 3 - A second user's normal order request failed during the DoS window.

Browser DevTools shows POST /dvsa/order returning 502 Bad Gateway while many order requests were in flight.

Screenshot 4 - CloudWatch/Lambda metrics confirm billing saturation.

DVSA-ORDER-BILLING reached 159 invocations, 413 throttles, max concurrency 4, 7 errors, and a minimum success rate of 53.33% during the test window.

Screenshot 5 - After throttling, excess requests are rejected with HTTP 429.

The same stress script now receives Too Many Requests responses, showing that abuse traffic is being rate-limited before every request can consume billing capacity.

## 6. Fix Strategy / Probable Mitigation

The mitigation is to reject abusive billing traffic before it reaches the expensive Lambda/payment path. API Gateway throttling/rate limiting should be enforced for billing requests so excess requests receive controlled HTTP 429 responses instead of consuming billing capacity.

The expected secure behaviour is that excess traffic receives controlled 429 Too Many Requests responses while legitimate billing remains available instead of degrading into 500/502 failures.

## 7. Code / Config Changes

Configuration change: API Gateway throttling/rate limiting was applied to the order billing endpoint so repeated requests are rejected with HTTP 429 before every request can invoke DVSA-ORDER-BILLING.

Configuration scope: no backend logic was changed for this lesson; the implemented mitigation was the API Gateway throttling/rate-limiting configuration.

Configuration scope: no additional Lambda configuration changes were included in this fix; the post-fix evidence focuses on the API Gateway 429 throttling behavior.

## 8. Verification After Fix

After the mitigation, the same bounded DoS script was run again. The output shows HTTP 429 Too Many Requests responses, which confirms that excessive traffic is being throttled instead of all requests reaching the billing Lambda.

The pre-fix evidence showed normal billing could succeed when the system was not under attack, while the attack produced 500/502 failures and Lambda throttling. The post-fix evidence demonstrates controlled rejection of abusive traffic, reducing the impact on the billing backend.

## 9. Structured Operation and Security Analysis

| Vulnerability | Intended Rule(s) | Artifacts Used to Infer Rule | Normal Behavior Evidence | Exploit Behavior Evidence |
| --- | --- | --- | --- | --- |
| Denial of Service (Lesson #6) | Authenticated users should be able to complete billing without another user's traffic exhausting shared billing/payment capacity. Expensive payment operations should be throttled/rate-limited client cannot consume all capacity. | Browser DevTools request results, curl/jq baseline billing response, stress-script HTTP status output, API Gateway response codes, and Lambda/CloudWatch metrics for DVSA-ORDER-BILLING. | A single normal billing request returned status ok, amount 72, and a payment token before the DoS test | During the flood, many billing requests returned HTTP 500/502, even for a second user, and Lambda metrics showed 159 invocations, 413 throttles, 7 errors, 53.33% minimum success rate, |

| Vulnerability | Why this is a Deviation | Deviation Class | Fix Applied (Where) | Post-Fix Verification | Optional Latency Before / After logging |
| --- | --- | --- | --- | --- | --- |
| Denial of Service (Lesson #6) | The system allowed repeated billing requests from one client to consume shared backend capacity, which caused unrelated legitimate billing requests to fail. This violates the intended availability rule for the payment workflow. | Intentional misuse / resource exhaustion | API Gateway throttling/rate limiting on POST /dvsa/order. | Re-running the stress script after the fix produced HTTP 429 Too Many Requests responses, proving excess traffic is being rejected before it can fully saturate billing | During attack: max duration about 6.33s from CloudWatch. Post-fix latency was not separately measured. |

## 10. Takeaway / Lessons Learned

This lesson shows that availability is a security requirement. Authentication alone does not protect an expensive serverless workflow from abuse. Billing and payment endpoints need per-user throttling and clear 429 behavior so one client's burst traffic cannot deny service to other users.
