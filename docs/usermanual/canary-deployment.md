---
title: Canary Deployment
layout: default
parent: User Manual
nav_order: 10
---

# Canary Deployment

Goma Gateway supports **canary deployments**, allowing you to gradually roll out new versions of your services while reducing risk. With this feature, you can send a controlled portion of traffic to a new backend (e.g., beta or staging), while the majority of requests continue to use the stable version.

This strategy is useful for:

* Testing new versions in production with a limited audience.
* Reducing the impact on potential bugs or regressions.
* Incrementally shifting traffic as confidence grows.

---

## Configuration Fields

* **`weight`** (`int`, required)
  Relative weight used when the backend competes for traffic with others in the
  same pool. Goma uses weighted-random selection — a backend's probability is
  `weight / sum(weights in the pool)`.

* **`exclusive`** (`boolean`, optional, default: `false`)
  Controls how a matching canary participates in routing:

    * **`true`** — If the request matches, this backend receives **100%** of
      the matching traffic (no split with stable backends). Use this for
      hard-pinned audiences such as internal staff or opted-in beta users.
    * **`false`** — If the request matches, this backend joins the stable
      backends in a **weighted pool** and competes for the request via its
      `weight`. Use this to send a fraction of a targeted audience to the
      canary while the rest continues to stable. Non-matching requests never
      see this backend.

* **`priority`** (`int`, optional, default: `0`)
  Resolves overlaps between **exclusive** canaries when more than one matches
  the same request. The highest `priority` wins; ties fall back to
  configuration order (the first matching backend in the list). Ignored for
  non-exclusive canaries, which always pool together.

* **`match`** (`[]object`, optional)
  A list of conditions used to determine whether traffic should be routed to this backend. Each condition supports the following fields:

    * **`source`** (`string`, required) — Where to extract the value from.
      Valid options: `header`, `query`, `cookie`, `ip`.

    * **`name`** (`string`, required) — The key to match (header name, query parameter, cookie name, or client IP).

    * **`operator`** (`string`, required) — How the extracted value should be compared. See [Operator Types](#operatortype).

    * **`value`** (`string`, required) — The value or values to match against. For operators like `in`, provide a comma-separated list.

---

## Source Types

* **`header`** — Match based on HTTP request headers.
* **`query`** — Match based on URL query parameters.
* **`cookie`** — Match based on cookies.
* **`ip`** — Match based on the client’s IP address.

---

## Operator Types

* **`equals`** — Value must exactly match the specified value.
* **`not_equals`** — Value must not equal the specified value.
* **`contains`** — Value must contain the given substring.
* **`not_contains`** — Value must not contain the given substring.
* **`starts_with`** — Value must start with the given substring.
* **`ends_with`** — Value must end with the given substring.
* **`regex`** — Value must match the given regular expression.
* **`in`** — Value must be one of the specified values (comma-separated).

---

## Example: Canary Deployment Configuration

```yaml
routes:
  - path: /
    name: canary
    enabled: true
    hosts:
      - api.example.com
    backends:
      - endpoint: "https://api-stable-example"
        weight: 80
      - endpoint: "https://api-beta-example"
        weight: 20
        exclusive: true
        match:
          - source: "header"
            name: "X-Canary-User"
            operator: "equals"
            value: "true"
          - source: "query"
            name: "version"
            operator: "equals"
            value: "beta"
          - source: "cookie"
            name: "beta_user"
            operator: "in"
            value: "admin,tester,developer"
```

In this configuration the beta backend is **exclusive**, so any request that
satisfies one of the match rules is routed to the beta backend in full; all
other traffic goes to the stable backend.

---

## Example: Non-Exclusive Canary (Partial Split)

Use a non-exclusive canary when you want a *fraction* of a targeted audience
to hit the canary while the rest continues to stable. The canary joins the
stable backends in a weighted pool for matching requests.

```yaml
routes:
  - path: /
    name: canary
    enabled: true
    hosts:
      - api.example.com
    backends:
      - endpoint: "https://api-stable-example"
        weight: 90
      - endpoint: "https://api-beta-example"
        weight: 10
        exclusive: false
        match:
          - source: "header"
            name: "X-Beta-Audience"
            operator: "equals"
            value: "true"
```

For requests **without** `X-Beta-Audience: true`, the canary is excluded —
100% of traffic goes to stable. For requests **with** the header, the pool is
`{stable(90), beta(10)}`, so roughly **10%** of those users are routed to the
canary and the remaining **90%** still hit stable. This gives you a gradual
ramp within a targeted segment.

---

## Example: Overlapping Exclusive Canaries with Priority

When several exclusive canaries could match the same request, use `priority`
to decide which one wins deterministically.

```yaml
backends:
  - endpoint: "https://api-stable-example"
    weight: 100
  - endpoint: "https://api-beta-example"
    weight: 20
    exclusive: true
    priority: 1
    match:
      - source: "header"
        name: "X-Beta-Audience"
        operator: "equals"
        value: "true"
  - endpoint: "https://api-staff-example"
    weight: 20
    exclusive: true
    priority: 10
    match:
      - source: "cookie"
        name: "group"
        operator: "equals"
        value: "staff"
```

A staff member who also has `X-Beta-Audience: true` matches both canaries; the
staff backend wins because its `priority` is higher. Equal priorities fall
back to the order the backends appear in the configuration.

