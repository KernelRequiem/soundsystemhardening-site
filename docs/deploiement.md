# Déploiement

Cette page reste au niveau des principes. Les détails opérationnels (hébergement, architecture précise, secrets) ne figurent pas dans ce dossier public, par choix de sécurité.

## Hébergement

Je gère l'infrastructure moi-même, sans dépendance à un opérateur cloud commercial. L'application est servie en HTTPS. Aucun tiers ne voit passer le trafic des visiteurs, et aucun outil de mesure d'audience externe n'est en place.

Ce choix découle de la mission du projet : un site qui enseigne à éviter la surveillance ne peut pas confier le trafic de ses visiteurs à un prestataire. Le passage en application serveur permet aussi de traiter les formulaires (email, signalement) sans dépendre d'un service externe qui lirait ces données.

## Pipeline

Le déploiement est automatisé depuis le dépôt :

```
git push  →  reconstruction automatique  →  mise en ligne (HTTPS)
```

Les mécanismes exacts de déclenchement et d'orchestration ne sont pas décrits ici.

## Commandes locales

```bash
npm install        # une seule fois
npm run dev        # http://localhost:4321
npm run build      # build de production
npm run preview    # prévisualisation locale
```

## Construction (`npm run build`)

Astro compile les pages statiques en HTML, génère l'index de recherche, prépare les routes serveur, Tailwind produit le CSS minimal, et les fichiers de `public/` sont copiés tels quels. Le résultat est un dossier `dist/` prêt à être servi.

## Sécurité

Aucun secret n'est dans le code : les identifiants vivent uniquement dans les variables d'environnement, et `.env` est exclu de git. Le HTTPS est forcé. L'environnement est durci (accès d'administration restreint, pare-feu, protection contre le brute-force, mises à jour automatiques). Les détails ne sont pas publiés, par principe.

## Contribuer au wiki

1. Ouvrir `src/content/wiki/` sur GitHub
2. Éditer ou créer un fichier `.md` via l'interface GitHub
3. Valider sur `main`

Le site se reconstruit et se redéploie automatiquement. Aucun terminal requis.
