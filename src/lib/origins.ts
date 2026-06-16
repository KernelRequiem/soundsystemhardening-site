/**
 * origins.ts, Origines autorisées (anti-CSRF) centralisées
 *
 * Le site public vit sur l'apex. La console d'administration HardeningCore
 * peut être servie sur une origine dédiée, restreinte au niveau réseau
 * (VPN/IP).
 *
 * Les endpoints d'écriture vérifient l'en-tête Origin pour bloquer les POST
 * cross-site (CSRF). Avec une origine admin distincte, le navigateur envoie
 * `Origin: https://admin.exemple.fr` : il faut donc l'accepter explicitement,
 * sinon toute action admin renverrait 403.
 *
 * Configuration (variables d'environnement de production) :
 *   PUBLIC_ORIGIN  = https://exemple.fr        (défaut)
 *   ADMIN_ORIGIN   = https://admin.exemple.fr  (optionnel)
 *
 * On n'élargit JAMAIS la liste au-delà de ces deux origines connues : pas de
 * wildcard, pas de reflet de l'Origin entrant.
 */

const DEFAULT_PUBLIC = 'https://soundsystemhardening.fr';

/** Origine canonique du site public (CORS des endpoints publics). */
export function publicOrigin(): string {
  return process.env.PUBLIC_ORIGIN || import.meta.env.PUBLIC_ORIGIN || DEFAULT_PUBLIC;
}

/** Origine de la console admin si servie sur un sous-domaine dédié, sinon null. */
export function adminOrigin(): string | null {
  const v = process.env.ADMIN_ORIGIN || import.meta.env.ADMIN_ORIGIN;
  return v ? String(v) : null;
}

/** Origines de confiance pour les écritures admin (apex + sous-domaine admin). */
export function allowedAdminOrigins(): string[] {
  const list = [publicOrigin()];
  const a = adminOrigin();
  if (a && !list.includes(a)) list.push(a);
  return list;
}

const LOCALHOST_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;

/**
 * Vérifie qu'une requête d'écriture admin provient d'une origine de confiance.
 * - origin absent (certains clients non-navigateur) : on laisse passer car la
 *   barrière forte reste le cookie de session signé vérifié en amont.
 * - localhost : accepté uniquement hors production (dev local).
 */
export function isTrustedAdminOrigin(origin: string | null): boolean {
  if (!origin) return true;
  if (allowedAdminOrigins().includes(origin)) return true;
  if (!import.meta.env.PROD && LOCALHOST_RE.test(origin)) return true;
  return false;
}
