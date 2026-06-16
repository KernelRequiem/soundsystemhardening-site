# Stack technique

## Framework : Astro

Le site utilise Astro en mode `server` (adaptateur Node). La grande majorité des pages sont pré-rendues en HTML statique au moment de la construction : rapides, sans calcul serveur à la volée. Seules quelques routes (les formulaires) exécutent réellement du code serveur. Un middleware applique les en-têtes de sécurité sur chaque réponse.

## Styles : Tailwind CSS

Les styles reposent sur Tailwind avec un design system à tokens (couleurs et espacements nommés). Voir [design-system.md](./design-system.md).

## Recherche : Fuse.js

Recherche floue qui fonctionne entièrement dans le navigateur, sans serveur, et qui tolère les fautes de frappe. Aucune requête de recherche n'est envoyée ni enregistrée.

## Carte : Leaflet

Carte interactive des incidents répressifs, rendue avec Leaflet et des tuiles OpenStreetMap.

## Polices : auto-hébergées

Les polices sont servies depuis le domaine du site, jamais depuis un fournisseur tiers. Charger une police depuis un service externe enregistrerait l'adresse IP de chaque visiteur chez ce tiers. Pour un projet qui enseigne à éviter la surveillance, c'était exclu.

## Formulaires : contact et signalement

Les formulaires de contact et de signalement sont les seules parties du site qui s'exécutent côté serveur. L'envoi d'email passe par un service de messagerie dont les identifiants vivent uniquement dans les variables d'environnement, jamais dans le code. Les signalements sont enregistrés dans une base de données externe via un jeton limité à l'écriture seule : même en cas de fuite, il ne permet pas de lire la base. Un piège anti-robot (honeypot) filtre les soumissions automatisées.

## Hors-ligne : Service Worker / PWA

Un service worker met en cache les pages vitales pour une consultation hors ligne.

## Tableau récapitulatif

| Composant | Technologie | Rôle |
|---|---|---|
| Framework | Astro (`output: server`) | Génération du site, routes serveur |
| CSS | Tailwind CSS | Styles utilitaires |
| Recherche | Fuse.js | Recherche fulltext côté navigateur |
| Carte | Leaflet | Carte interactive des incidents |
| Polices | Auto-hébergées | Aucun contact avec un tiers |
| Email | Service SMTP externe | Formulaire de contact |
| Signalements | Base de données externe | Incidents (écriture seule côté serveur) |
| Hors-ligne | Service Worker / PWA | Consultation sans réseau |
| Hébergement | Infrastructure auto-gérée | Voir [déploiement](./deploiement.md) |
