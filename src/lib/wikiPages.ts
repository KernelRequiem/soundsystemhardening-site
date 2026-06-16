// src/lib/wikiPages.ts
// Source unique de vérité pour la liste des pages wiki réellement publiées.
// Utilisée par l'index /wiki, le compteur de la page d'accueil et l'index de
// recherche, afin que les trois affichent toujours le même nombre, calculé
// dynamiquement à partir des fichiers réels. Toute nouvelle page .md est prise
// en compte automatiquement, sans toucher au code.

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export const WIKI_DIR = join(process.cwd(), 'src/content/wiki');

// Pages présentes sur le disque mais volontairement non listées :
//  - Home           : page d'accueil du wiki GitHub, redondante avec l'index /wiki
//  - Axe-sanitaire  : doublon de la page Sanitaire (déjà listée dans Stratégie)
//  - strategie-wiki : note de travail interne, pas une page de contenu
//  - Phalsbourg...  : brouillon "à compléter", dépubliée tant que les faits ne sont
//                     pas sourcés (on n'expose pas une page creuse sur du répressif)
const HIDDEN = new Set([
  'Home',
  'Axe-sanitaire',
  'strategie-wiki',
  'Phalsbourg-Succes-Absence-Intervention',
]);

/**
 * Slugs des pages wiki publiées, triés (locale fr).
 * Exclut les fichiers structurels (_Sidebar, _Footer), les fragments (*_<n>)
 * et les pages masquées ci-dessus.
 */
export function listWikiSlugs(): string[] {
  return readdirSync(WIKI_DIR)
    .filter((f) => f.endsWith('.md') && !f.startsWith('_'))
    .map((f) => f.slice(0, -3))
    .filter((slug) => !HIDDEN.has(slug) && !/_\d+$/.test(slug))
    .sort((a, b) => a.localeCompare(b, 'fr'));
}

/**
 * Une page est-elle publiée ? (sert à bloquer l'accès direct par URL aux pages
 * masquées/structurelles/fragments, en plus de leur exclusion de l'index.)
 */
export function isPublishedSlug(slug: string): boolean {
  if (!slug || slug.startsWith('_')) return false;
  if (HIDDEN.has(slug) || /_\d+$/.test(slug)) return false;
  return true;
}

/** Titre d'une page wiki (premier H1, emojis retirés) avec repli sur le slug. */
export function getWikiTitle(slug: string): string {
  try {
    const raw = readFileSync(join(WIKI_DIR, `${slug}.md`), 'utf-8');
    const m = raw.match(/^#\s+(.+)$/m);
    if (!m) return slug.replace(/-/g, ' ');
    return m[1]
      .replace(/[\u{1F000}-\u{1FFFF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/gu, '')
      .trim();
  } catch {
    return slug.replace(/-/g, ' ');
  }
}
