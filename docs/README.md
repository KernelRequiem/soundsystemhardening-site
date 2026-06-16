# Documentation technique

Ce dossier `docs/` n'est pas publié sur le site. Il documente comment j'ai construit le projet et pourquoi, pour les contributeurs et pour la maintenance dans le temps.

Par principe de sécurité, les détails opérationnels (configuration d'hébergement, secrets, règles réseau) ne figurent pas ici.

## Sommaire

1. [Stack technique](./stack.md)
2. [Architecture du projet](./architecture.md)
3. [Fonctionnalités](./fonctionnalites.md)
4. [Design system](./design-system.md)
5. [Déploiement](./deploiement.md)

## Vue d'ensemble

SoundSystemHardening est un wiki d'autodéfense juridique et numérique pour le mouvement free party.

Techniquement, c'est une application Astro en mode `server` : la quasi-totalité du site est pré-générée en pages HTML statiques au moment de la construction, ce qui le rend rapide et difficile à attaquer. Seules quelques routes serveur (les formulaires de contact et de signalement) s'exécutent à la demande.

Je gère l'hébergement moi-même, sur une infrastructure que je contrôle, sans dépendance à un opérateur cloud commercial. Aucun tiers ne voit passer le trafic des visiteurs : c'est la condition de base pour un projet qui enseigne à se protéger de la surveillance.
