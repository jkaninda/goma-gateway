---
title: OpenID Connect
layout: default
parent: Middlewares
nav_order: 6
---

# OpenID Connect middleware

The `oidc` middleware terminates the browser login flow at the gateway. It sends
unauthenticated users to your identity provider, keeps the session at the edge,
verifies it on every request, and projects the authenticated user's claims onto
the proxied request — so your backends stay stateless and never handle a token.

`type: oauth` and `type: oauth2` are deprecated aliases for the same middleware.

## Minimal configuration

```yaml
middlewares:
  - name: sso
    type: oidc
    paths: ["/.*"]
    rule:
      issuer: https://authentik.example.com/application/o/goma/
      clientId: xxx
      clientSecret: xxx
      scopes: [openid, email, profile]
```

The issuer alone is enough: the authorization, token, user info and JWKS
endpoints all come from the provider's discovery document, which is cached for
an hour. Register `https://<your-host>/oauth2/callback` as the redirect URI with
your provider, or set `callbackPath` to match what you have already registered.

## What happens on a request

1. No session → the browser is redirected to the provider with a random `state`,
   a `nonce`, and a PKCE `S256` challenge. The URL the user asked for is
   remembered in a sealed, short-lived cookie.
2. The provider returns to `callbackPath`. The gateway checks the state against
   that cookie, exchanges the code with the PKCE verifier, verifies the ID
   token's signature, issuer, audience and nonce, and opens a session.
3. On later requests the session is verified, refreshed when the access token
   has expired, and the user's claims are projected onto the upstream request.
4. `logoutPath` ends the session, and the provider's session too when it
   advertises `end_session_endpoint`.

Requests without a valid session are redirected only when the caller is a
browser navigating. API clients and XHR/`fetch` requests get a `401` with a
`WWW-Authenticate` header instead of a redirect they cannot follow.

## How a session is verified

| Token shape                                          | How it is verified                                                                 |
|------------------------------------------------------|------------------------------------------------------------------------------------|
| JWT access token, JWKS known                         | Signature against the provider's JWKS, plus `exp`, and `iss`/`aud` when configured |
| Opaque access token (Google, GitHub, Facebook)       | The provider's user info endpoint, whose response also supplies the claims          |
| ID token, JWKS known                                 | Signature, `exp`, `nonce` at sign-in, and `aud` — which must be your `clientId`     |

Only asymmetric signing algorithms are accepted, so a token cannot be forged by
signing `HS256` with the provider's public key as the HMAC secret.

**The gateway must have some way to verify tokens.** An `issuer` provides one
through discovery; otherwise set `endpoint.jwksUrl` or `endpoint.userInfoUrl`.
Without any of them the middleware refuses to load rather than appear to guard
the route. User info responses are cached for 60 seconds per token, which is
also how long a revoked opaque token keeps working.

## Configuration

| Option                | Type    | Description                                                                                    |
|-----------------------|---------|--------------------------------------------------------------------------------------------------|
| `clientId`            | string  | The application's client ID. Required.                                                            |
| `clientSecret`        | string  | The application's client secret. Required.                                                        |
| `issuer`              | string  | Enables discovery, and is enforced as the `iss` claim on JWT tokens.                                |
| `provider`            | string  | `google`, `gitlab`, `github`, `amazon`, `facebook` or `custom`. Fills in known endpoints.          |
| `endpoint.authUrl`    | string  | Authorization endpoint. Overrides discovery.                                                       |
| `endpoint.tokenUrl`   | string  | Token endpoint. Overrides discovery.                                                               |
| `endpoint.jwksUrl`    | string  | JWKS used to verify JWT access tokens and ID tokens.                                               |
| `endpoint.userInfoUrl`| string  | User info endpoint, used to verify opaque tokens and to read claims.                                |
| `audience`            | string  | Enforced as the `aud` claim on JWT **access** tokens when set.                                      |
| `scopes`              | list    | Requested scopes.                                                                                  |
| `callbackPath`        | string  | Where the provider returns the user. Defaults to `<route path>/oauth2/callback`.                    |
| `logoutPath`          | string  | Ends the session when requested. Not registered unless set.                                        |
| `postLoginRedirect`   | string  | Where users land after signing in. Empty returns them to the URL they asked for.                    |
| `postLogoutRedirect`  | string  | Where users land after signing out. Defaults to `/`.                                                |
| `pkce`                | boolean | Proof key for the code exchange. Enabled unless set to `false`.                                     |
| `session`             | map     | Where the session is kept. See below.                                                              |
| `claimsExpression`    | string  | Authorizes the user against their claims. Same syntax as the [JWT middleware](jwt.md).              |
| `claimsSource`        | list    | Where claims are read from, in increasing precedence: `access_token`, `userinfo`, `id_token`.       |
| `forward`             | map     | How the user's claims reach your backend. See below.                                               |

### Sessions

```yaml
      session:
        store: redis        # cookie (default) | memory | redis
        secret: ${SESSION_SECRET}
        ttl: 12h
        idleTimeout: 1h
        cookie:
          name: goma_session
          path: /
          sameSite: lax
```

| Store    | Behaviour                                                                                                 |
|----------|------------------------------------------------------------------------------------------------------------|
| `cookie` | The whole session lives in the browser, sealed with AES-GCM and split across cookies when large. No shared state, so it works across replicas out of the box. |
| `memory` | Sessions live in this process. They do not survive a restart and are not shared between replicas.            |
| `redis`  | Sessions live in Redis, shared across replicas and surviving restarts. Requires Redis on the gateway.         |

Session data is always sealed, whether it sits in a cookie or in Redis: a stolen
cookie or a Redis dump does not hand over anyone's tokens. `secret` defaults to
the client secret, which every replica serving the route already shares —
changing it ends all existing sessions.

Cookie sessions carry the tokens and the claims on every request. A user in many
groups can outgrow what browsers accept; the gateway refuses to write a session
it could not read back and tells you to move to `store: redis`.

Without a `session` block the cookie is scoped to the route path, so two routes
on the same host do not share a session.

### Forwarding user info to your backend

`forward` projects the verified claims onto the proxied request as headers,
query parameters and cookies:

```yaml
      forward:
        headers:
          X-Auth-User: sub
          X-Auth-Email: email
          X-Auth-Name: "{{ .given_name }} {{ .family_name }}"   # template
          X-Auth-Groups: groups                                  # array → "a,b"
          X-Auth-Tenant: resource_access.app.tenant              # nested claim
        query:
          uid: sub
        cookies:
          app_user: email
        accessTokenHeader: Authorization                         # Bearer <token>
```

| Option              | Type    | Description                                                                                          |
|---------------------|---------|--------------------------------------------------------------------------------------------------------|
| `headers`           | map     | Header name → claim path or template.                                                                   |
| `query`             | map     | Query parameter → claim path or template.                                                               |
| `cookies`           | map     | Cookie name → claim path or template. Added to the upstream request only, never to the client response. |
| `stripInbound`      | boolean | Remove client-supplied copies of every mapped key. Default `true`.                                      |
| `arraySeparator`    | string  | Joins array claims such as `groups`. Default `,`.                                                       |
| `encoding`          | string  | `auto` (default) base64-encodes non-ASCII values with a `<Header>-Encoding` companion; `raw` does not.   |
| `maxValueBytes`     | int     | Bounds a single projected value. Default `4096`.                                                        |
| `accessTokenHeader` | string  | Forward the raw access token, e.g. `Authorization`.                                                     |
| `idTokenHeader`     | string  | Forward the raw ID token, e.g. `X-Auth-Id-Token`.                                                       |

A value is either a claim path — with dot notation for nested objects — or a
template interpolating several of them. Arrays are joined with `arraySeparator`,
booleans become `true`/`false`, and nested objects are forwarded as compact
JSON. A claim that is not present leaves the key absent rather than forwarding
an empty value.

**Do not disable `stripInbound`.** Every mapped key is removed from the incoming
request before the verified value is set, on every path of the route — including
the ones this middleware does not guard. Without that, a client can simply send
`X-Auth-Email: admin@example.com` and your backend will believe it. Plain
headers are only as trustworthy as the network between the gateway and your
backend; on an untrusted network, have the backend verify the token itself via
`accessTokenHeader` or `idTokenHeader`.

### Authorization

Authenticating a user is not the same as allowing them in. `claimsExpression`
decides who gets through:

```yaml
      claimsExpression: "Contains('groups', 'engineering') && Equals('email_verified', true)"
```

Users who sign in but do not match get a `403`, at the callback and on every
later request. See the [JWT middleware](jwt.md#claims-validation) for the full
expression syntax.

## Example: Authentik with discovery

```yaml
middlewares:
  - name: sso
    type: oidc
    paths: ["/.*"]
    rule:
      issuer: https://authentik.example.com/application/o/goma/
      clientId: xxx
      clientSecret: xxx
      scopes: [openid, email, profile]
      callbackPath: /oauth2/callback
      logoutPath: /oauth2/logout
      claimsExpression: "Contains('groups', 'engineering')"
      session:
        store: redis
        ttl: 12h
        idleTimeout: 1h
      forward:
        headers:
          X-Auth-User: sub
          X-Auth-Email: email
          X-Auth-Name: "{{ .given_name }} {{ .family_name }}"
          X-Auth-Groups: groups
```

## Example: Google

```yaml
middlewares:
  - name: google-sso
    type: oidc
    paths: ["/.*"]
    rule:
      provider: google
      clientId: xxx
      clientSecret: xxx
      scopes:
        - https://www.googleapis.com/auth/userinfo.email
        - https://www.googleapis.com/auth/userinfo.profile
      callbackPath: /oauth2/callback
      postLoginRedirect: /dashboard
      forward:
        headers:
          X-Auth-User: id
          X-Auth-Email: email
          X-Auth-Name: name
```

Google issues opaque access tokens, so sessions are verified against Google's
user info endpoint, which is also where these claims come from.

### Apply the middleware on a route

```yaml
  routes:
    - path: /protected
      name: sso-route
      rewrite: /
      backends:
        - endpoint: https://example.com
      middlewares:
        - sso
```

## Migrating from `type: oauth`

Existing configurations keep working; the gateway logs which field to move to.

| Old field      | Replacement                                                     |
|----------------|-------------------------------------------------------------------|
| `redirectUrl`  | `callbackPath` — the URL is derived from the request              |
| `redirectPath` | `postLoginRedirect`                                                |
| `cookiePath`   | `session.cookie.path`                                              |
| `state`        | Removed. The state is now random per login, as CSRF protection requires. |

Sessions are stored in a new sealed format, so everyone signs in once more after
the upgrade. Consider replacing the explicit `endpoint` block with `issuer` and
letting discovery fill it in.
