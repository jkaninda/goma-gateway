import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

/**
 * Navigation for the v1 documentation.
 *
 * The v0.x site grew a single "User Manual" section that had become a grab bag
 * of fourteen unrelated pages. For v1 the same pages are grouped by the task a
 * reader is actually doing — configuring, shaping traffic, securing it,
 * observing it — so nothing has to be hunted for. File paths are unchanged, so
 * every published URL still resolves.
 */
const sidebars: SidebarsConfig = {
  docsSidebar: [
    {
      type: 'category',
      label: 'Getting Started',
      collapsed: false,
      items: [
        'index',
        'why-use-goma-gateway',
        'quickstart/index',
        {
          type: 'category',
          label: 'Installation',
          link: {type: 'doc', id: 'install/index'},
          items: ['install/docker', 'install/kubernetes'],
        },
      ],
    },
    {
      type: 'category',
      label: 'Configuration',
      link: {type: 'doc', id: 'usermanual/index'},
      items: [
        'usermanual/gateway',
        'usermanual/route',
        'usermanual/extra-config',
        'usermanual/providers',
      ],
    },
    {
      type: 'category',
      label: 'Traffic Management',
      items: [
        'monitoring-and-performance/load-balancing',
        'usermanual/healthcheck',
        'usermanual/canary-deployment',
        'usermanual/tcp-udp-grpc',
        'usermanual/maintenance-mode',
        'usermanual/error-interceptor',
        'usermanual/cors',
      ],
    },
    {
      type: 'category',
      label: 'Security & TLS',
      items: [
        'usermanual/tls',
        'usermanual/mtls',
        'usermanual/running-behind-a-proxy',
      ],
    },
    {
      type: 'category',
      label: 'Middlewares',
      link: {type: 'doc', id: 'middlewares/index'},
      items: [
        'middlewares/overview',
        {
          type: 'category',
          label: 'Authentication',
          items: [
            'middlewares/basic',
            'middlewares/jwt',
            'middlewares/oidc',
            'middlewares/oauth',
            'middlewares/ldap',
            'middlewares/forward-auth',
          ],
        },
        {
          type: 'category',
          label: 'Access Control',
          items: [
            'middlewares/access',
            'middlewares/access-policy',
            'middlewares/geo-block',
            'middlewares/user-agent-block',
            'middlewares/rate-limit',
            'middlewares/body-limit',
          ],
        },
        {
          type: 'category',
          label: 'Request & Response',
          items: [
            'middlewares/add-prefix',
            'middlewares/rewrite-regex',
            'middlewares/strip-query',
            'middlewares/request-headers',
            'middlewares/response-headers',
            'middlewares/http-caching',
          ],
        },
        {
          type: 'category',
          label: 'Redirects',
          items: [
            'middlewares/redirect',
            'middlewares/redirect-regex',
            'middlewares/redirect-scheme',
          ],
        },
        {
          type: 'category',
          label: 'Observability & Errors',
          items: ['middlewares/access-log', 'middlewares/error-interceptor'],
        },
      ],
    },
    {
      type: 'category',
      label: 'Observability',
      link: {type: 'doc', id: 'monitoring-and-performance/index'},
      items: [
        'monitoring-and-performance/monitoring',
        'monitoring-and-performance/logging',
        'monitoring-and-performance/analytics',
        'monitoring-and-performance/distributed-instances',
      ],
    },
    {
      type: 'category',
      label: 'Kubernetes Operator',
      link: {type: 'doc', id: 'operator-manual/index'},
      items: [
        'operator-manual/installation',
        'operator-manual/gateway',
        'operator-manual/route',
        'operator-manual/middleware',
        'operator-manual/uninstall',
      ],
    },
    {
      type: 'category',
      label: 'Extending Goma',
      items: ['usermanual/module'],
    },
    {
      type: 'category',
      label: 'Upgrade Notes',
      link: {type: 'doc', id: 'upgrade/index'},
      items: [
        'upgrade/v1.0',
        'upgrade/v0.7.0',
        'upgrade/v0.6.0',
        'upgrade/v0.3.0',
        'upgrade/v0.2.8',
        'upgrade/v0.2.4',
      ],
    },
    {
      type: 'link',
      label: 'CRD Reference',
      href: 'https://doc.crds.dev/github.com/jkaninda/goma-operator',
    },
  ],
};

export default sidebars;
