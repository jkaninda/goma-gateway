import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Goma Gateway',
  tagline:
    'A high-performance, security-focused API Gateway for modern developers and cloud-native environments',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: 'https://goma.jkaninda.dev',
  baseUrl: '/',

  organizationName: 'jkaninda',
  projectName: 'goma-gateway',

  onBrokenLinks: 'throw',
  onBrokenAnchors: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  markdown: {
    mermaid: true,
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/jkaninda/goma-gateway/tree/main/docs/',
          // Docs are served from the site root so the URLs the Jekyll site
          // published for three years keep working (only the `.html` suffix
          // changes, and plugin-client-redirects covers that).
          routeBasePath: '/',
          showLastUpdateTime: true,
          // v1 is what visitors get at the root; v0.15 stays browsable at
          // /0.15/ for deployments that have not upgraded yet.
          lastVersion: 'current',
          versions: {
            current: {
              label: 'v1',
              path: '',
              badge: false,
            },
            '0.15': {
              label: 'v0.15',
              path: '0.15',
              banner: 'unmaintained',
            },
          },
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
        sitemap: {
          changefreq: 'weekly',
          priority: 0.5,
        },
      } satisfies Preset.Options,
    ],
  ],

  plugins: [
    [
      '@docusaurus/plugin-client-redirects',
      {
        // The Jekyll site published every page with a `.html` suffix for three
        // years. Docusaurus serves them extensionless, so map the old form onto
        // the new one and keep the accumulated inbound links working.
        createRedirects(existingPath: string) {
          if (existingPath === '/' || existingPath.endsWith('/')) {
            return undefined;
          }
          return [`${existingPath}.html`];
        },
        // Pages renamed for v1, where the old name was a typo. Both the `.html`
        // and extensionless forms are covered.
        redirects: [
          {
            to: '/middlewares/body-limit',
            from: ['/middlewares/boy-limit', '/middlewares/boy-limit.html'],
          },
          {
            to: '/monitoring-and-performance/distributed-instances',
            from: [
              '/monitoring-and-performance/distrubuted-intance',
              '/monitoring-and-performance/distrubuted-intance.html',
            ],
          },
          {
            to: '/monitoring-and-performance/load-balancing',
            from: [
              '/monitoring-and-performance/loadbalanging',
              '/monitoring-and-performance/loadbalanging.html',
            ],
          },
          {
            to: '/operator-manual/middleware',
            from: ['/operator-manual/middlware', '/operator-manual/middlware.html'],
          },
          {
            to: '/operator-manual/uninstall',
            from: [
              '/operator-manual/Uninstallation',
              '/operator-manual/Uninstallation.html',
            ],
          },
          {
            to: '/usermanual/tcp-udp-grpc',
            from: [
              '/usermanual/tcp-and-upd-proxy',
              '/usermanual/tcp-and-upd-proxy.html',
            ],
          },
        ],
      },
    ],
  ],

  themes: [
    '@docusaurus/theme-mermaid',
    [
      '@easyops-cn/docusaurus-search-local',
      {
        hashed: true, // cache-bust the index when content changes
        indexBlog: false, // blog is disabled above
        docsRouteBasePath: '/',
        highlightSearchTermsOnTargetPage: true,
        searchResultLimits: 10,
        explicitSearchResultPath: true,
      },
    ],
  ],

  themeConfig: {
    image: 'img/goma-gateway.png',
    colorMode: {
      defaultMode: 'light',
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'Goma Gateway',
      logo: {
        alt: 'Goma Gateway logo',
        src: 'img/logo.png',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Documentation',
        },
        {
          type: 'docsVersionDropdown',
          position: 'right',
          dropdownActiveClassDisabled: true,
        },
        {
          href: 'https://doc.crds.dev/github.com/jkaninda/goma-operator',
          label: 'CRD Reference',
          position: 'right',
        },
        {
          href: 'https://github.com/jkaninda/goma-gateway',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {label: 'Overview', to: '/'},
            {label: 'Quickstart', to: '/quickstart/'},
            {label: 'Installation', to: '/install/'},
            {label: 'Upgrade Notes', to: '/upgrade/'},
          ],
        },
        {
          title: 'Reference',
          items: [
            {label: 'User Manual', to: '/usermanual/'},
            {label: 'Middlewares', to: '/middlewares/'},
            {label: 'Kubernetes Operator', to: '/operator-manual/'},
            {
              label: 'CRD Reference',
              href: 'https://doc.crds.dev/github.com/jkaninda/goma-operator',
            },
          ],
        },
        {
          title: 'Project',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/jkaninda/goma-gateway',
            },
            {
              label: 'Kubernetes Operator',
              href: 'https://github.com/jkaninda/goma-operator',
            },
            {
              label: 'Report an issue',
              href: 'https://github.com/jkaninda/goma-gateway/issues',
            },
          ],
        },
      ],
      copyright: `Copyright © 2024-${new Date().getFullYear()} <a href="https://www.jkaninda.dev" target="_blank" rel="noopener">Jonas Kaninda</a>. Distributed under the Apache-2.0 License.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'json', 'go', 'yaml', 'toml', 'docker', 'nginx'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
