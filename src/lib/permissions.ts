/**
 * permissions.ts, Modèle d'autorisations centralisé de HardeningCore
 *
 * Source de vérité UNIQUE : qui (rôle) peut faire quoi (permission). Les pages et
 * les endpoints ne testent JAMAIS un rôle en dur (`role === 'admin'`), ils
 * demandent une permission nommée via can()/requirePermission(). Ajouter un rôle
 * (juriste, rédacteur…) ou déplacer un droit = une seule ligne ici, sans toucher
 * au reste du code. C'est plus sûr (intentions explicites) et plus évolutif.
 *
 * Politique actuelle :
 *   - admin      : accès TOTAL (toutes les permissions).
 *   - moderator  : modération, édition wiki, gestion carte ; lecture seule sur
 *                  l'historique ; pas d'accès supervision ni validation légale.
 */

import type { AdminRole } from './adminAuth';

// ── Catalogue des permissions (verbes métier, pas des routes) ──────────
export type Permission =
  // Wiki
  | 'wiki.view' | 'wiki.edit'
  // Modération des contributions
  | 'moderation.view' | 'moderation.review' | 'moderation.import'
  // Carte / incidents
  | 'incident.view' | 'incident.edit'
  // Validation légale
  | 'legal.view' | 'legal.validate'
  // Historique
  | 'history.view'
  // Supervision système
  | 'monitoring.view'
  // Dashboard de pilotage stratégique
  | 'dashboard.view' | 'dashboard.manage'
  // Outils
  | 'spotcheck.use';

// ── Matrice rôle → permissions ─────────────────────────────────────────
// '*' = toutes les permissions (raccourci pour l'admin). Pour un rôle restreint,
// on liste explicitement ce qu'il a le droit de faire (principe du moindre privilège).
const MATRIX: Record<AdminRole, Permission[] | '*'> = {
  admin: '*',
  moderator: [
    'wiki.view', 'wiki.edit',
    'moderation.view', 'moderation.review', 'moderation.import',
    'incident.view', 'incident.edit',
    'legal.view',        // peut consulter le statut légal (lecture seule)
    'history.view',      // peut consulter l'historique (lecture seule)
    'dashboard.view',    // peut consulter le cockpit (lecture seule)
    'spotcheck.use',
    // PAS de legal.validate (validation juridique réservée admin)
    // PAS de monitoring.view (supervision système réservée admin)
    // PAS de dashboard.manage (édition du suivi outreach réservée admin)
  ],
};

// ── API ────────────────────────────────────────────────────────────────
/** Vrai si le rôle possède la permission demandée. Un rôle inconnu n'a rien. */
export function can(role: AdminRole | undefined, perm: Permission): boolean {
  if (!role) return false;
  const grants = MATRIX[role];
  if (grants === undefined) return false;
  if (grants === '*') return true;
  return grants.includes(perm);
}

/** Liste résolue des permissions d'un rôle (utile pour la nav / le debug). */
export function permissionsFor(role: AdminRole | undefined): Permission[] {
  if (!role) return [];
  const grants = MATRIX[role];
  if (grants === '*') return ALL_PERMISSIONS.slice();
  return grants ?? [];
}

// Liste exhaustive (sert à résoudre '*' et à d'éventuels contrôles).
export const ALL_PERMISSIONS: Permission[] = [
  'wiki.view', 'wiki.edit',
  'moderation.view', 'moderation.review', 'moderation.import',
  'incident.view', 'incident.edit',
  'legal.view', 'legal.validate',
  'history.view', 'monitoring.view',
  'dashboard.view', 'dashboard.manage',
  'spotcheck.use',
];

/** Libellés lisibles (pour affichage d'un éventuel écran de droits). */
export const PERMISSION_LABELS: Record<Permission, string> = {
  'wiki.view': 'Consulter le wiki', 'wiki.edit': 'Éditer le wiki',
  'moderation.view': 'Voir la modération', 'moderation.review': 'Modérer (valider/rejeter)', 'moderation.import': 'Importer les issues GitHub',
  'incident.view': 'Voir la carte', 'incident.edit': 'Gérer les incidents',
  'legal.view': 'Voir la validation légale', 'legal.validate': 'Valider juridiquement',
  'history.view': "Voir l'historique", 'monitoring.view': 'Supervision système',
  'dashboard.view': 'Voir le dashboard', 'dashboard.manage': 'Piloter le dashboard (outreach)',
  'spotcheck.use': 'Utiliser SpotCheck',
};
