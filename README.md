# SoundSystemHardening

Wiki d'autodéfense juridique et numérique pour le mouvement free party : droits face aux forces de l'ordre, sécurité numérique (OpSec), stratégie de résistance, outils de terrain.

Site en production : [soundsystemhardening.fr](https://soundsystemhardening.fr)

## Ce que c'est

Une application web qui rassemble une soixantaine de pages de wiki juridique et opérationnel, une carte interactive des incidents répressifs, un arbre de décision pour le terrain, et plusieurs outils côté client (chiffrement de messages, nettoyage de métadonnées d'images, horodatage, génération de documents).

Principe directeur : un site qui enseigne à se protéger de la surveillance ne doit lui-même exposer aucune donnée de ses visiteurs. Chaque choix technique en découle.

## Stack

Application Astro 4 en mode `server` (adaptateur Node). La quasi-totalité des pages sont pré-rendues en HTML statique ; seules quelques routes (formulaires) s'exécutent côté serveur. Toute la logique sensible (chiffrement, nettoyage de métadonnées, génération de documents) tourne dans le navigateur, jamais sur le serveur.

| Couche | Technologie |
|---|---|
| Framework | Astro 4 (`output: server`, adaptateur Node) |
| Styles | Tailwind CSS 3 |
| Recherche | Fuse.js (fulltext côté navigateur) |
| Carte | Leaflet + tuiles OpenStreetMap |
| Outils client | AES-GCM 256 / PBKDF2, Web Crypto, génération PDF en mémoire |
| Polices | Auto-hébergées |
| Hors-ligne | Service Worker / PWA |

## Démarrage local

```bash
npm install        # une seule fois
npm run dev        # http://localhost:4321
npm run build      # build de production
npm run preview    # prévisualisation locale
```

Les variables d'environnement nécessaires aux formulaires sont décrites dans [`.env.example`](./.env.example). Le fichier `.env` réel n'est jamais versionné.

## Contribuer au wiki

Ajouter ou corriger une page ne demande aucune compétence en développement :

1. Ouvrir `src/content/wiki/` sur GitHub
2. Éditer un fichier `.md` ou en créer un via l'interface GitHub
3. Valider sur `main`

Le site se reconstruit et se redéploie automatiquement.

## Documentation

Le dossier [`docs/`](./docs/) couvre la stack, l'architecture, les fonctionnalités et le design system.

## Licence

Contenu sous licence CC BY-SA 4.0.
