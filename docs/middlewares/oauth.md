---
title: OAuth auth
layout: default
parent: Middlewares
nav_order: 6
---

# OAuth middleware

The OAuth middleware terminates the browser login flow at the gateway. It sends
unauthenticated users to your identity provider, verifies the session on every
request, and projects the authenticated user's claims onto the proxied request
so your backends can stay stateless and never handle a token.

## How a session is verified

Every request carrying a session is verified before it reaches your backend:

| Token shape                                        | How it is verified                                                                 |
|----------------------------------------------------|------------------------------------------------------------------------------------|
| JWT access token, `endpoint.jwksUrl` configured    | Signature against the provider's JWKS, plus `exp`, and `iss`/`aud` when configured |
| Opaque access token (Google, GitHub, Facebook)     | The provider's `endpoint.userInfoUrl`, whose response also supplies the claims      |
| ID token (`id_token`), `endpoint.jwksUrl` configured | Signature, `exp`, and `aud` — which must be this middleware's `clientId`           |

Only asymmetric signing algorithms are accepted, so a token cannot be forged by
signing `HS256` with the provider's public key as the HMAC secret.

**At least one of `endpoint.jwksUrl` or `endpoint.userInfoUrl` is required.**
Without one the gateway has no way to tell a token issued by your provider from
one a client made up, so the middleware refuses to load rather than appear to
guard the route. For the well-known providers both are filled in for you.

User info responses are cached for 60 seconds per token, which is also how long
a token revoked at the provider keeps working when the provider issues opaque
tokens.

## Configuration

| Option                | Type   | Description                                                                                   |
|-----------------------|--------|-----------------------------------------------------------------------------------------------|
| `clientId`            | string | The application's client ID. Required.                                                         |
| `clientSecret`        | string | The application's client secret. Required.                                                     |
| `provider`            | string | `google`, `gitlab`, `github`, `amazon`, `facebook` or `custom`. Defaults to `custom`.           |
| `endpoint.authUrl`    | string | Authorization endpoint. Filled in for known providers.                                          |
| `endpoint.tokenUrl`   | string | Token endpoint. Filled in for known providers.                                                  |
| `endpoint.jwksUrl`    | string | JWKS used to verify JWT access tokens and ID tokens.                                            |
| `endpoint.userInfoUrl`| string | User info endpoint, used to verify opaque tokens and to read claims.                             |
| `redirectUrl`         | string | Callback URL registered with the provider. Required.                                            |
| `redirectPath`        | string | Path to send the user to after login, e.g. `/dashboard`.                                        |
| `cookiePath`          | string | Path the session cookies are scoped to. Defaults to the route path.                             |
| `scopes`              | list   | Requested scopes.                                                                               |
| `state`               | string | Opaque state value sent to the provider.                                                        |
| `issuer`              | string | Enforced as the `iss` claim on JWT tokens when set.                                             |
| `audience`            | string | Enforced as the `aud` claim on JWT **access** tokens when set.                                   |
| `claimsSource`        | list   | Where claims are read from, in increasing precedence: `access_token`, `userinfo`, `id_token`.    |
| `forward`             | map    | How the user's claims are projected onto the upstream request. See below.                        |

Session cookies (`goma_access_token`, `goma_refresh_token`, `goma_id_token`) are
issued as `HttpOnly`, `SameSite=Lax`, and `Secure` whenever the request arrived
over TLS.

Requests without a valid session are redirected to the provider only when the
caller is a browser navigating. API clients and XHR/`fetch` requests receive a
`401` with a `WWW-Authenticate` header instead of a redirect they cannot follow.

## Forwarding user info to your backend

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
| `encoding`          | string  | `auto` (default) or `raw`. See [Encoding](#encoding).                                                   |
| `maxValueBytes`     | int     | Bounds a single projected value. Default `4096`.                                                        |
| `accessTokenHeader` | string  | Forward the raw access token, e.g. `Authorization` or `X-Auth-Access-Token`.                             |
| `idTokenHeader`     | string  | Forward the raw ID token, e.g. `X-Auth-Id-Token`.                                                       |

### Claim paths and templates

A value is either a claim path — with dot notation for nested objects, such as
`resource_access.app.tenant` — or a template interpolating several of them,
such as `{{ .given_name }} {{ .family_name }}`. Arrays are joined with
`arraySeparator`; booleans become `true`/`false`; nested objects are forwarded
as compact JSON. A claim that is not present leaves the key absent rather than
forwarding an empty value.

The same syntax is used by the [JWT middleware](jwt.md), so a claim path means
the same thing wherever you write it.

### Do not disable `stripInbound`

Every mapped key is removed from the incoming request before the verified value
is set, on every path of the route — including the ones this middleware does
not guard. Without that, a client can simply send `X-Auth-Email: admin@example.com`
and your backend will believe it. Set `stripInbound: false` only when nothing
but the gateway can reach the upstream.

Plain headers are only as trustworthy as the network path between the gateway
and your backend. On an untrusted network, prefer having the backend verify the
token itself via `accessTokenHeader` or `idTokenHeader`.

### Encoding

HTTP headers are restricted to ASCII. With `encoding: auto`, a value that is
not pure ASCII — a display name, typically — is base64-encoded and flagged with
a companion header, so `X-Auth-Name` arrives with `X-Auth-Name-Encoding: base64`.
Use `encoding: raw` to pass values through untouched. Control characters are
always removed, so a claim a user can set for themselves cannot inject a second
header into the proxied request.

## Example: Google

```yaml
middlewares:
  - name: google-oauth
    type: oauth
    paths:
      - /*
    rule:
      clientId: xxx
      clientSecret: xxxx
      # oauth provider google, gitlab, github, amazon, facebook, custom
      provider: google # facebook, gitlab, github, amazon
      redirectUrl: https://example.com/callback/protected
      # RedirectPath is the PATH to redirect users after authentication, e.g: /my-protected-path/dashboard
      redirectPath: /dashboard
      scopes:
        - https://www.googleapis.com/auth/userinfo.email
        - https://www.googleapis.com/auth/userinfo.profile
      state: randomStateString
      forward:
        headers:
          X-Auth-User: id
          X-Auth-Email: email
          X-Auth-Name: name
```

Google issues opaque access tokens, so sessions are verified against Google's
user info endpoint, which is also where these claims come from.

## Example: Authentik

```yaml
middlewares:
    - name: oauth-authentik
      type: oauth
      paths:
        - /protected
        - /example-of-oauth
      rule:
        clientId: xxx
        clientSecret: xxx
        # oauth provider google, gitlab, github, amazon, facebook, custom
        provider: custom
        endpoint:
          authUrl: https://authentik.example.com/application/o/authorize/
          tokenUrl: https://authentik.example.com/application/o/token/
          userInfoUrl: https://authentik.example.com/application/o/userinfo/
          jwksUrl: https://authentik.example.com/application/o/goma/jwks/
        issuer: https://authentik.example.com/application/o/goma/
        redirectUrl: https://example.com/callback # Goma will use the callback path as path
        # RedirectPath is the PATH to redirect users after authentication, e.g: /my-protected-path/dashboard
        redirectPath: ''
        # CookiePath e.g.: /my-protected-path or / || by default is applied on a route path
        cookiePath: "/"
        scopes:
          - email
          - openid
          - profile
        state: randomStateString
        forward:
          headers:
            X-Auth-User: sub
            X-Auth-Email: email
            X-Auth-Name: "{{ .given_name }} {{ .family_name }}"
            X-Auth-Groups: groups
          accessTokenHeader: Authorization
```

### Apply middleware on the route

```yaml
  ##### Define routes
  routes:
    - path: /protected
      name: oauth-route
      rewrite: /
      backends:
       - endpoint: https://example.com
      methods: [POST, PUT, GET]
      healthCheck: {}
      cors: {}
      middlewares:
        - oauth-authentik
```

## Current limitations

- `state` is a fixed configured value rather than a per-request random value,
  and the flow does not yet use PKCE or an OIDC `nonce`.
- After login the user lands on `redirectPath`, not on the URL they originally
  requested.
- There is no logout endpoint; clearing the session cookies ends the session.
- Sessions live entirely in the browser's cookies. Each request refreshes on its
  own, so with a provider that rotates refresh tokens, concurrent requests can
  race.
