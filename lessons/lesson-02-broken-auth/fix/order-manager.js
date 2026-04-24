const serialize = require("node-serialize");
const { LambdaClient, InvokeCommand } = require("@aws-sdk/client-lambda");
const {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
} = require("@aws-sdk/client-cognito-identity-provider");
const jose = require("node-jose");

const https = require("https");
let _jwksCache = { keystore: null, fetchedAt: 0 };

function resp(statusCode, bodyObj) {
  return {
    statusCode,
    headers: { "Access-Control-Allow-Origin": "*" },
    body: JSON.stringify(bodyObj),
  };
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(e);
            }
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
          }
        });
      })
      .on("error", reject);
  });
}

async function getCognitoKeystore() {
  const now = Date.now();
  if (_jwksCache.keystore && now - _jwksCache.fetchedAt < 6 * 60 * 60 * 1000) {
    return _jwksCache.keystore;
  }
  const region = process.env.AWS_REGION;
  const userPoolId = process.env.userpoolid;
  const jwksUrl = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
  const jwks = await fetchJson(jwksUrl);
  const keystore = await jose.JWK.asKeyStore(jwks);
  _jwksCache = { keystore, fetchedAt: now };
  return keystore;
}
  
async function verifyCognitoJwt(jwt) {
  const region = process.env.AWS_REGION;
  const userPoolId = process.env.userpoolid;
  const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
  const keystore = await getCognitoKeystore();
  const result = await jose.JWS.createVerify(keystore).verify(jwt);
  const claims = JSON.parse(result.payload.toString("utf8"));
  if (claims.iss !== issuer) throw new Error("bad issuer");
  if (typeof claims.exp === "number" && Date.now() / 1000 > claims.exp)
    throw new Error("expired");
  if (claims.token_use && !["access", "id"].includes(claims.token_use))
    throw new Error("bad token_use");
  return claims;
}

exports.handler = (event, context, callback) => {
  // console.log(JSON.stringify(event));
  var req = serialize.unserialize(event.body);
  var headers = serialize.unserialize(event.headers);
  var auth_header = headers.Authorization || headers.authorization || "";
  var jwt = auth_header.replace(/^Bearer\s+/i, "").trim();
  if (!jwt) {
    return callback(
      null,
      resp(401, { status: "err", msg: "missing authorization" }),
    );
  }
  verifyCognitoJwt(jwt)
    .then((claims) => {
      var user = claims.username || claims["cognito:username"] || claims.sub;
      if (!user) {
        return callback(
          null,
          resp(401, { status: "err", msg: "missing subject" }),
        );
      }
      var isAdmin = false;

      var params = {
        UserPoolId: process.env.userpoolid,
        Username: user,
      };

      try {
        const cognitoidentityserviceprovider =
          new CognitoIdentityProviderClient();
        const command = new AdminGetUserCommand(params);
        const userData = cognitoidentityserviceprovider.send(command);

        userData.then((userData) => {
          // console.log("userData", JSON.stringify(userData));
          var len = Object.keys(userData.UserAttributes).length;
          for (var i = 0; i < len; i++) {
            if (userData.UserAttributes[i].Name === "custom:is_admin") {
              isAdmin = userData.UserAttributes[i].Value;
              break;
            }
          }
          var action = req.action;
          var isOk = true;
          var payload = {};
          var functionName = "";

          switch (action) {
            case "new":
              payload = {
                user: user,
                cartId: req["cart-id"],
                items: req["items"],
              };
              functionName = "DVSA-ORDER-NEW";
              break;

            case "update":
              payload = {
                user: user,
                orderId: req["order-id"],
                items: req["items"],
              };
              functionName = "DVSA-ORDER-UPDATE";
              break;

            case "cancel":
              payload = { user: user, orderId: req["order-id"] };
              functionName = "DVSA-ORDER-CANCEL";
              break;

            case "get":
              payload = {
                user: user,
                orderId: req["order-id"],
                isAdmin: isAdmin,
              };
              functionName = "DVSA-ORDER-GET";
              break;

            case "orders":
              payload = { user: user };
              functionName = "DVSA-ORDER-ORDERS";
              break;

            case "account":
              payload = { user: user };
              functionName = "DVSA-USER-ACCOUNT";
              break;

            case "profile":
              payload = { user: user, profile: req["data"] };
              functionName = "DVSA-USER-PROFILE";
              break;

            case "shipping":
              payload = {
                user: user,
                orderId: req["order-id"],
                shipping: req["data"],
              };
              functionName = "DVSA-ORDER-SHIPPING";
              break;

            case "billing":
              payload = {
                user: user,
                orderId: req["order-id"],
                billing: req["data"],
              };
              functionName = "DVSA-ORDER-BILLING";
              break;

            case "complete":
              payload = { orderId: req["order-id"] };
              functionName = "DVSA-ORDER-COMPLETE";
              break;

            case "inbox":
              payload = { action: "inbox", user: user };
              functionName = "DVSA-USER-INBOX";
              break;

            case "message":
              payload = {
                action: "get",
                user: user,
                msgId: req["msg-id"],
                type: req["type"],
              };
              functionName = "DVSA-USER-INBOX";
              break;

            case "delete":
              payload = { action: "delete", user: user, msgId: req["msg-id"] };
              functionName = "DVSA-USER-INBOX";
              break;

            case "upload":
              payload = { user: user, file: req["attachment"] };
              functionName = "DVSA-FEEDBACK-UPLOADS";
              break;

            case "feedback":
              const response = {
                statusCode: 200,
                headers: {
                  "Access-Control-Allow-Origin": "*",
                },
                body: JSON.stringify({
                  status: "ok",
                  message: `Thank you ${req["data"]["name"]}.`,
                }),
              };
              callback(null, response);

            case "admin-orders":
              if (isAdmin == "true") {
                payload = { user: user, data: req["data"] };
                functionName = "DVSA-ADMIN-GET-ORDERS";
                break;
              } else {
                const response = {
                  statusCode: 403,
                  headers: {
                    "Access-Control-Allow-Origin": "*",
                  },
                  body: JSON.stringify({
                    status: "err",
                    message: "Unauthorized",
                  }),
                };
                callback(null, response);
              }

            default:
              isOk = false;
          }

          if (isOk == true) {
            var params = {
              FunctionName: functionName,
              InvocationType: "RequestResponse",
              Payload: JSON.stringify(payload),
            };
            const lambda_client = new LambdaClient();
            const command = new InvokeCommand(params);
            lambda_client.send(command).then((lambda_response) => {
              const data = JSON.parse(
                Buffer.from(lambda_response.Payload).toString(),
              );
              const response = {
                statusCode: 200,
                headers: {
                  "Access-Control-Allow-Origin": "*",
                },
                body: JSON.stringify(data),
              };
              callback(null, response);
            });
          } else {
            var data = { status: "err", msg: "unknown action" };
            const response = {
              statusCode: 200,
              headers: {
                "Access-Control-Allow-Origin": "*",
              },
              body: JSON.stringify(data),
            };
            callback(null, response);
          }
        });
      } catch (e) {
        console.log(e);
      }
    })
    .catch((e) => {
      console.log("JWT verify failed:", e);
      return callback(null, resp(401, { status: "err", msg: "invalid token" }));
    });
};
