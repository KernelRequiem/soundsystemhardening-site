# Architecture du projet

## Structure des dossiers

```
src/
├── components/        Composants réutilisables
├── content/wiki/      Pages du wiki (Markdown)
├── data/              incidents.json (carte), decision.ts (arbre de décision)
├── layouts/           Layout universel
├── pages/             Une page = une URL
│   └── api/           Routes serveur : contact, signalement, santé
├── scripts/           Logique TypeScript des outils
└── styles/            CSS global

public/                Fichiers servis tels quels (polices, favicons, manifest, service worker)
docs/                  Cette documentation (non publiée sur le site)
```

## Statique d'abord, serveur quand il le faut

Le site fonctionne en mode `server` (adaptateur Node) avec un rendu majoritairement statique :

La quasi-totalité des pages (accueil, wiki, urgence, outils) sont pré-rendues en HTML au moment de la construction. Elles ne déclenchent aucun calcul serveur à l'ouverture, ce qui les rend rapides et réduit la surface d'attaque.

Seules les routes qui en ont besoin sont rendues côté serveur à la demande : envoyer un email, traiter un signalement, répondre à un test de santé. Un middleware applique les en-têtes de sécurité sur chaque réponse.

## Routing

Astro utilise un routing basé sur les fichiers : chaque fichier dans `src/pages/` correspond à une URL. Le fichier `src/pages/wiki/[slug].astro` est une route dynamique : il génère autant de pages HTML qu'il y a de fichiers Markdown dans le wiki.

## Données

`incidents.json` contient les incidents répressifs (date, département, type, description, coordonnées) qui alimentent la carte et le compteur de l'accueil.

`decision.ts` contient l'arbre de décision (questions, réponses, nœuds de résultat). Le format TypeScript permet de typer la structure et d'attraper les erreurs dès la construction.

## Système wiki

Chaque fichier `src/content/wiki/*.md` devient une page web : à la construction, `src/pages/wiki/[slug].astro` lit tous les fichiers Markdown, les convertit en HTML et les injecte dans le layout. Les fichiers Markdown sont la source de vérité, éditables directement sur GitHub, sans aucun CMS.

## Ce qui n'est pas publié sur le site

Le dossier `docs/` est en dehors de `src/`, donc ignoré à la construction. Il reste visible sur GitHub mais n'apparaît pas sur le site.
