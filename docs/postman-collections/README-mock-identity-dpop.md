# Mock-identity collections: Bearer and DPoP

Two collections share one environment:

| Postman name | File | What it does |
|---|---|---|
| `certify- Mock IDA` | `inji-certify-with-mock-identity.postman_collection.json` | Bearer credential issuance |
| `certify- Mock IDA - DPoP` | `inji-certify-with-mock-identity-dpop.postman_collection.json` | DPoP-constrained issuance (RFC 9449) |
| `certify-mock env` | `inji-certify-with-mock-identity.postman_environment.json` | shared by both |

Both collections must use the **same** environment. The Bearer collection's
`Get Tokens V2` publishes `unbound_access_token` into it, and the DPoP
scenarios use that as the "token with no `cnf.jkt`" fixture.

## Run order

1. `certify- Mock IDA` → **VCI** folder, top to bottom.
   `Authorize / OAuthdetails request V2` must run before `Send OTP` — it sets
   `transaction_id`, `oauth_details_key` and `oauth_details_hash`.
2. `certify- Mock IDA - DPoP` → **VCI (DPoP)** folder (steps 1–8, in order).
3. `certify- Mock IDA - DPoP` → **DPoP scenarios**. These depend on both
   `access_token` (bound, from step 2) and `unbound_access_token` (from step 1).

## Switching deployments

The environment ships pointing at a **local** deployment. To run against MOSIP's
released/collab deployment, change these five variables — nothing else:

| Variable | Local (as shipped) | MOSIP released (collab) |
|---|---|---|
| `authServerUrl` | `http://localhost:8188/v1/esignet` | `https://esignet-mock.collab.mosip.net/v1/esignet` |
| `aud` | `http://localhost:8188/v1/esignet/oauth/v2/token` | `https://esignet-mock.collab.mosip.net/v1/esignet/oauth/v2/token` |
| `audUrl` | `http://localhost:8091` | `http://certify-nginx:80` |
| `mockIdentitySystemUrl` | `http://localhost:8182/v1/mock-identity-system` | `https://api.collab.mosip.net/v1/mock-identity-system` |
| `relayingPartyId` | `mock-relying-party-id` | `mpartner-default-esignet` |

`certifyUrl` is `http://localhost:8091/v1/certify` in both — the docker-compose
stack publishes certify on the same host port.

### `audUrl` is certify's identifier, not an endpoint

`Get Farmer Credential` signs the OpenID4VCI proof with `"aud": audUrl`. It must
equal the `credential_issuer` value that certify advertises at
`GET {{certifyUrl}}/.well-known/openid-credential-issuer` — **not** the
credential endpoint URL. Both a wrong host and the endpoint URL itself fail the
same way, with `400 invalid_proof`.

### The DPoP collection cannot run against collab

Switching the five variables makes the **Bearer** collection work against
collab. It will not make the DPoP collection work: DPoP arrived in eSignet
**1.8**, and the collab mock runs an older build that advertises no
`dpop_signing_alg_values_supported` and issues tokens with no `cnf.jkt`. Without
that claim certify can only ever answer "access token is not DPoP-bound", so
every DPoP scenario fails by construction.

The DPoP collection needs an authorization server at eSignet 1.8 or later.

## Client registration

Two OIDC clients are expected, differing only in `dpop_bound_access_tokens`:

| Env variable | Client id | `dpop_bound_access_tokens` | Used by |
|---|---|---|---|
| `clientId` | `wallet-demo` | `false` | Bearer flow; also the unbound-token fixture |
| `dpopClientId` | `dpop-wallet-demo` | `true` | DPoP flow |

Both authenticate with `private_key_jwt`. Register each with the public half of
the matching environment key — `privateKey_jwk` and `dpop_privateKey_jwk`.

They cannot share one key: eSignet enforces a unique public key per client and
rejects the second registration with `duplicate_public_key`.

Note `wallet_private_key` is a **different** key again — it signs the DPoP
proofs and is what `cnf.jkt` fingerprints. `dpop_privateKey_jwk` proves *which
client* is calling; `wallet_private_key` proves *which sender* holds the token.

## Notes

- **CSRF.** eSignet 1.8 (Spring Security 6, BREACH protection) puts the raw
  token in the `XSRF-TOKEN` cookie and a masked token in the response body.
  `X-XSRF-TOKEN` must carry the **body** value; sending the cookie value gives
  `403 Forbidden` with an empty `path`.
- **DPoP nonce.** eSignet always rejects the first DPoP token request with
  `400 use_dpop_nonce` and a `DPoP-Nonce` header. Step 6 retries automatically
  with the nonce folded into the proof; this is expected, not a failure.
- **PKCE.** `codeVerifier`, `codeChallenge`, `codeChallengeMethod`, `code` and
  `client_assertion` are collection-scoped in both collections and deliberately
  absent from the environment. An environment variable of the same name would
  shadow the collection value — an empty one breaks PKCE with
  `unsupported_pkce_challenge_method`.
