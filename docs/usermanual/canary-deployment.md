---
title: Canary Deployment
layout: default
parent: User Manual
nav_order: 9
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
  Percentage of traffic to route to this backend.

* **`exclusive`** (`boolean`, optional, default: `false`)
  When `true`, this backend only receives traffic if the specified **match** conditions are met.

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

In this configuration:

* **80% of traffic** goes to the stable backend (`api-stable-example`).
* **20% of traffic** goes to the beta backend (`api-beta-example`), but **only if** requests match at least one of the defined conditions (e.g., a header, query parameter, or cookie indicating canary usage).

