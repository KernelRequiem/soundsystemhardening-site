import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import mdx from '@astrojs/mdx';
import node from '@astrojs/node';

import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://soundsystemhardening.fr',
  output: 'server',
  adapter: node({ mode: 'standalone' }),
  // Barre d'outils de dev desactivee : son app "Menu" tente un appel reseau
  // (fetchLatestAstroVersion) qui echoue derriere VPN/reseau filtre, ce qui
  // provoque l'erreur "Cannot read properties of undefined (latestAstroVersion)".
  // La barre est un confort de dev sans impact sur le build/prod.
  devToolbar: { enabled: false },
  integrations: [
    tailwind(),
    mdx(),
    // Le sitemap ne doit jamais référencer la console d'administration ni les
    // endpoints internes : on exclut /hardeningcore/* par sécurité (défense en
    // profondeur, en plus du noindex et de l'isolation par sous-domaine + VPN).
    sitemap({
      filter: (page) => !page.includes('/hardeningcore'),
    }),
  ],
  markdown: {
    shikiConfig: {
      theme: 'github-dark',
      wrap: true,
    },
  },
});