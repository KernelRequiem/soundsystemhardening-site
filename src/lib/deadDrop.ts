/**
 * deadDrop.ts, Logique serveur de la « Boîte aux lettres morte » (Dead Drop)
 *
 * Une interface publique côté client transforme anonymement une saisie texte en
 * Issue GitHub sur un dépôt PRIVÉ. Ce module porte tout ce qui doit rester côté
 * serveur : génération/vérification du proof-of-work, rate-limit dédié, et
 * validation/sanitisation des champs. Le secret PoW et le PAT GitHub ne quittent
 * JAMAIS le serveur.
 *
 * Modèle de menace couvert ici :
 *  - Bots de spam de masse           → proof-of-work (coût CPU client) + honeypot
 *  - Rejeu d'un challenge résolu      → challenge signé HMAC, horodaté, à usage unique
 *  - Inondation d'Issues via le PAT   → rate-limit dédié en mémoire (par IP)
 *  - Issues géantes / DoS payload     → limites de taille strictes
 *  - Injection d'en-tête / titre forgé → neutralisation des retours à la ligne
 *
 * Ce que le PoW NE couvre PAS : un attaquant déterminé peut résoudre le PoW en
 * boucle (le calcul est public). C'est un ralentisseur, pas un mur. Le vrai
 * garde-fou contre l'abus du PAT est le rate-limit serveur ci-dessous, plus le
 * fait que la destination est un repo privé (le contenu n'est pas exposé).
 */

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';

// ── Paramètres ────────────────────────────────────────────────────────────────

/** Difficulté du proof-of-work : nombre de bits nuls de tête exigés sur le hash. */
export const POW_DIFFICULTY_BITS = 18; // ~quelques centaines de ms sur un navigateur récent

/** Durée de validité d'un challenge PoW (anti-rejeu différé). */
export const POW_TTL_MS = 5 * 60 * 1000; // 5 minutes

/** Rate-limit DÉDIÉ au Dead Drop (plus strict que le rate-limit global du middleware). */
export const DROP_RL_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
export const DROP_RL_MAX = 3;                     // 3 soumissions ACCEPTÉES / IP / fenêtre

/** Limites de taille (anti-DoS, anti-Issue géante). */
export const LIMITS = {
  title: 200,
  body: 8000,
  contact: 80,
  // ── Mode édition contextuelle ──
  selection: 2000, // passage cité par le visiteur
  before: 2000,    // texte actuel (correction)
  after: 2000,     // texte proposé (correction)
  pageUrl: 300,
  pageTitle: 300,
  section: 300,
} as const;

/** Sous-types d'édition contextuelle proposables sur une sélection. */
export const EDIT_KINDS = {
  correction: 'Correction',
  comment: 'Commentaire / suggestion',
  source: 'Ajout de source',
  factual: 'Erreur factuelle',
} as const;
export type EditKind = keyof typeof EDIT_KINDS;

/** Types de contribution autorisés (alignés sur la modale). On n'accepte rien d'autre. */
export const DROP_TYPES = {
  bug: 'Signalement de Bug',
  juridique: 'Ajout Juridique',
  feature: 'Idée de Fonctionnalité',
} as const;
export type DropType = keyof typeof DROP_TYPES;

// ── Secret PoW ──────────────────────────────────────────────────────────────
// Sert à signer les challenges. À défaut de DROP_POW_SECRET on retombe sur
// ADMIN_SECRET (déjà présent et requis en prod). Sans aucun secret on génère une
// valeur volatile au boot : les challenges restent valides le temps d'un process,
// ce qui suffit (TTL 5 min) mais signifie qu'un redémarrage invalide les challenges
// en vol, comportement acceptable et fail-safe.
let VOLATILE_SECRET: string | null = null;
function powSecret(): string {
  const s = process.env.DROP_POW_SECRET || import.meta.env.DROP_POW_SECRET
    || process.env.ADMIN_SECRET || import.meta.env.ADMIN_SECRET;
  if (s) return String(s);
  if (!VOLATILE_SECRET) VOLATILE_SECRET = randomBytes(32).toString('hex');
  return VOLATILE_SECRET;
}

// ── Challenge PoW ────────────────────────────────────────────────────────────

export interface PowChallenge {
  /** Préfixe aléatoire à inclure dans le hash (lie la solution à ce challenge). */
  prefix: string;
  /** Horodatage d'émission (ms epoch). */
  ts: number;
  /** Difficulté exigée (bits de tête nuls). */
  bits: number;
  /** Signature HMAC du triplet (prefix|ts|bits) : empêche de forger un challenge. */
  sig: string;
}

/** Émet un challenge signé. Aucun état serveur stocké : tout est dans la signature. */
export function issueChallenge(): PowChallenge {
  const prefix = randomBytes(12).toString('hex');
  const ts = Date.now();
  const bits = POW_DIFFICULTY_BITS;
  const sig = signChallenge(prefix, ts, bits);
  return { prefix, ts, bits, sig };
}

function signChallenge(prefix: string, ts: number, bits: number): string {
  return createHmac('sha256', powSecret())
    .update(`${prefix}|${ts}|${bits}`)
    .digest('hex');
}

/** Comparaison à temps constant de deux hex de même longueur. */
function safeEqualHex(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
  } catch {
    return false;
  }
}

// ── Vérification de la solution ──────────────────────────────────────────────

/**
 * Compte les bits de tête à zéro d'un digest hex (SHA-256).
 * Un PoW « N bits » exige que sha256(prefix + nonce) commence par N zéros binaires.
 */
export function leadingZeroBits(hexDigest: string): number {
  let bits = 0;
  for (let i = 0; i < hexDigest.length; i++) {
    const nibble = parseInt(hexDigest[i], 16);
    if (nibble === 0) { bits += 4; continue; }
    // Bits de tête nuls dans ce nibble non nul (0..3).
    if (nibble < 2) bits += 3;
    else if (nibble < 4) bits += 2;
    else if (nibble < 8) bits += 1;
    break;
  }
  return bits;
}

import { createHash } from 'crypto';

export interface PowSolution {
  prefix: string;
  ts: number;
  bits: number;
  sig: string;
  nonce: string; // trouvé par le client
}

export interface PowResult { ok: boolean; error?: string }

/**
 * Vérifie qu'une solution PoW est valide :
 *  1. la signature du challenge est authentique (non forgé) ;
 *  2. le challenge n'est pas expiré (TTL) ni daté du futur ;
 *  3. sha256(prefix|nonce) présente bien le nombre de bits de tête exigé.
 */
export function verifySolution(sol: PowSolution): PowResult {
  if (!sol || typeof sol.prefix !== 'string' || typeof sol.nonce !== 'string') {
    return { ok: false, error: 'Preuve manquante.' };
  }
  if (sol.bits !== POW_DIFFICULTY_BITS) {
    return { ok: false, error: 'Difficulté invalide.' };
  }
  const expectedSig = signChallenge(sol.prefix, sol.ts, sol.bits);
  if (!safeEqualHex(expectedSig, sol.sig)) {
    return { ok: false, error: 'Challenge non authentique.' };
  }
  const age = Date.now() - sol.ts;
  if (age < -60_000 || age > POW_TTL_MS) {
    return { ok: false, error: 'Challenge expiré, recharge la page.' };
  }
  // Borne la taille du nonce pour éviter un hash sur une entrée gigantesque.
  if (sol.nonce.length > 64) return { ok: false, error: 'Nonce invalide.' };

  const digest = createHash('sha256').update(`${sol.prefix}|${sol.nonce}`).digest('hex');
  if (leadingZeroBits(digest) < sol.bits) {
    return { ok: false, error: 'Preuve de travail insuffisante.' };
  }
  return { ok: true };
}

// ── Anti-rejeu : un challenge résolu n'est consommable qu'une fois ───────────
// La signature seule autorise le rejeu pendant le TTL. On mémorise les prefixes
// déjà consommés (TTL borné) pour qu'une même preuve ne crée pas N Issues.
const usedPrefixes = new Map<string, number>(); // prefix -> expiry ts

export function consumeChallengeOnce(prefix: string): boolean {
  const now = Date.now();
  // Purge opportuniste.
  if (usedPrefixes.size > 10_000) {
    for (const [k, exp] of usedPrefixes) if (exp <= now) usedPrefixes.delete(k);
  }
  if (usedPrefixes.has(prefix)) return false; // déjà utilisé
  usedPrefixes.set(prefix, now + POW_TTL_MS);
  return true;
}

// ── Rate-limit dédié (IP) ────────────────────────────────────────────────────
// Distinct du rate-limit global (8 POST/10min toutes routes confondues). Ici on
// ne compte QUE les soumissions Dead Drop ACCEPTÉES, pour brider la création
// d'Issues via le PAT indépendamment du reste du trafic API.
const dropBuckets = new Map<string, number[]>();

export function isDropRateLimited(ip: string): boolean {
  const now = Date.now();
  const hits = (dropBuckets.get(ip) || []).filter((t) => now - t < DROP_RL_WINDOW_MS);
  if (hits.length >= DROP_RL_MAX) {
    dropBuckets.set(ip, hits); // pas d'ajout : on bloque
    return true;
  }
  return false;
}

export function recordDropHit(ip: string): void {
  const now = Date.now();
  const hits = (dropBuckets.get(ip) || []).filter((t) => now - t < DROP_RL_WINDOW_MS);
  hits.push(now);
  dropBuckets.set(ip, hits);
  if (dropBuckets.size > 5000) {
    for (const [k, v] of dropBuckets) {
      if (v.every((t) => now - t >= DROP_RL_WINDOW_MS)) dropBuckets.delete(k);
    }
  }
}

// ── Validation / sanitisation des champs ─────────────────────────────────────

export interface DropInput {
  type?: unknown;
  body?: unknown;
  contact?: unknown;
}

export interface CleanDrop {
  type: DropType;
  typeLabel: string;
  body: string;
  contact: string; // déjà nettoyé, peut être vide
}

export interface ValidationResult {
  ok: boolean;
  error?: string;
  data?: CleanDrop;
}

/** Neutralise les retours à la ligne (champs qui alimentent le titre de l'Issue). */
function oneLine(s: string): string {
  return s.replace(/[\r\n\t]+/g, ' ').trim();
}

export function validateDrop(input: DropInput): ValidationResult {
  const typeRaw = typeof input.type === 'string' ? input.type.trim() : '';
  if (!(typeRaw in DROP_TYPES)) {
    return { ok: false, error: 'Type de contribution invalide.' };
  }
  const type = typeRaw as DropType;

  const body = typeof input.body === 'string' ? input.body : '';
  if (!body.trim()) return { ok: false, error: 'Le contenu est vide.' };
  if (body.length > LIMITS.body) return { ok: false, error: 'Contenu trop long.' };

  let contact = typeof input.contact === 'string' ? oneLine(input.contact) : '';
  if (contact.length > LIMITS.contact) return { ok: false, error: 'Contact trop long.' };

  return {
    ok: true,
    data: {
      type,
      typeLabel: DROP_TYPES[type],
      body: body.trim(),
      contact,
    },
  };
}

// ── Sanitisation du texte non fiable destiné à une Issue Markdown ────────────
// Le passage cité et les champs avant/après proviennent de la PAGE ou de la
// SAISIE du visiteur : c'est du contenu NON FIABLE qui va être rendu en Markdown
// par GitHub. Trois risques à neutraliser :
//   1. Sortie de bloc de code : un ``` dans le texte casserait notre fence et
//      laisserait le reste s'interpréter comme du Markdown (images, liens,
//      mentions @user qui spammeraient des tiers). On échappe les backticks.
//   2. Mentions / références involontaires : @login et #123 déclenchent des
//      notifications ou liens d'Issues. Sans interprétation Markdown (grâce au
//      bloc de code) ils restent inertes, mais on cloisonne quand même.
//   3. Payload géant : on tronque à la limite.
//
// Stratégie : on présente TOUJOURS le texte non fiable dans un bloc de code
// clôturé par un fence dynamique (suite de ~ plus longue que toute séquence de ~
// présente dans le texte), ce qui rend l'évasion de bloc impossible.

/** Tronque proprement en signalant la coupe. */
function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + '\n…[tronqué]';
}

/**
 * Emballe du texte non fiable dans un bloc de code Markdown inviolable.
 * Le fence est une suite de '~' strictement plus longue que la plus longue
 * suite de '~' du contenu : impossible pour le texte de refermer le bloc.
 * (On utilise '~' et non '`' car le contenu contient souvent des backticks.)
 */
export function fenceUntrusted(raw: string, max: number): string {
  const text = truncate(String(raw), max);
  // Plus longue séquence de ~ dans le texte.
  let longest = 0;
  const matches = text.match(/~+/g);
  if (matches) for (const m of matches) longest = Math.max(longest, m.length);
  const fence = '~'.repeat(Math.max(3, longest + 1));
  // On retire un éventuel caractère NUL (parfois mal géré) sans toucher au reste.
  const clean = text.replace(/ /g, '');
  return `${fence}\n${clean}\n${fence}`;
}

/**
 * Nettoie une valeur courte qui ira sur UNE ligne de métadonnée (URL, titre,
 * section). On neutralise les retours à la ligne ET les caractères Markdown
 * actifs en tête de ligne, et on borne la taille. On n'émet jamais ce texte
 * hors d'un contexte échappé.
 */
function metaLine(raw: unknown, max: number): string {
  if (typeof raw !== 'string') return '';
  // Une seule ligne, backticks neutralisés pour rester dans un span de code.
  return oneLine(raw).replace(/`/g, '′').slice(0, max);
}

/** Valide qu'une URL de page est bien interne au site (anti-URL piégée). */
function safePageUrl(raw: unknown): string {
  const s = metaLine(raw, LIMITS.pageUrl);
  // On n'accepte qu'un chemin relatif commençant par '/' (pas de http(s):// ni
  // de javascript:). Le contexte est notre propre site : une URL absolue ou un
  // schéma exotique n'a rien à faire ici et serait un vecteur d'hameçonnage.
  if (!s.startsWith('/')) return '';
  if (/[\s<>`"']/.test(s)) return '';
  return s;
}

// ── Validation du mode édition contextuelle ──────────────────────────────────

export interface EditInput {
  editKind?: unknown;
  pageUrl?: unknown;
  pageTitle?: unknown;
  section?: unknown;
  selection?: unknown; // passage cité
  before?: unknown;    // correction : texte actuel
  after?: unknown;     // correction : texte proposé
  comment?: unknown;   // commentaire / justification / source selon le type
  contact?: unknown;
}

export interface CleanEdit {
  editKind: EditKind;
  editLabel: string;
  pageUrl: string;
  pageTitle: string;
  section: string;
  selection: string;
  before: string;
  after: string;
  comment: string;
  contact: string;
}

export function validateEdit(input: EditInput): { ok: boolean; error?: string; data?: CleanEdit } {
  const kindRaw = typeof input.editKind === 'string' ? input.editKind.trim() : '';
  if (!(kindRaw in EDIT_KINDS)) return { ok: false, error: 'Type d\'édition invalide.' };
  const editKind = kindRaw as EditKind;

  const selection = typeof input.selection === 'string' ? input.selection : '';
  // La sélection est le cœur du mode édition : sans elle, pas de contexte.
  if (!selection.trim()) return { ok: false, error: 'Aucun passage sélectionné.' };
  if (selection.length > LIMITS.selection) return { ok: false, error: 'Passage trop long.' };

  const before = typeof input.before === 'string' ? input.before : '';
  const after = typeof input.after === 'string' ? input.after : '';
  const comment = typeof input.comment === 'string' ? input.comment : '';

  // Contraintes par type : une correction exige une proposition ; les autres un commentaire.
  if (editKind === 'correction' && !after.trim()) {
    return { ok: false, error: 'Propose un texte corrigé.' };
  }
  if (editKind !== 'correction' && !comment.trim()) {
    return { ok: false, error: 'Ajoute une explication.' };
  }
  if (before.length > LIMITS.before || after.length > LIMITS.after) {
    return { ok: false, error: 'Texte trop long.' };
  }
  if (comment.length > LIMITS.body) return { ok: false, error: 'Explication trop longue.' };

  let contact = typeof input.contact === 'string' ? oneLine(input.contact) : '';
  if (contact.length > LIMITS.contact) return { ok: false, error: 'Contact trop long.' };

  return {
    ok: true,
    data: {
      editKind,
      editLabel: EDIT_KINDS[editKind],
      pageUrl: safePageUrl(input.pageUrl),
      pageTitle: metaLine(input.pageTitle, LIMITS.pageTitle),
      section: metaLine(input.section, LIMITS.section),
      selection: selection.trim(),
      before: before.trim(),
      after: after.trim(),
      comment: comment.trim(),
      contact,
    },
  };
}

// ── Construction de l'Issue GitHub ───────────────────────────────────────────

export interface GithubIssuePayload {
  title: string;
  body: string;
  labels: string[];
}

/** Map sous-type d'édition → label GitHub. */
const EDIT_LABEL: Record<EditKind, string> = {
  correction: 'correction',
  comment: 'commentaire',
  source: 'source',
  factual: 'factuel',
};

/**
 * Construit l'Issue d'une édition contextuelle. Tout le contenu non fiable
 * (citation, before/after, commentaire) passe par fenceUntrusted() : il est
 * affiché en bloc de code inviolable, jamais interprété comme du Markdown.
 * Les métadonnées (page, section) sont déjà nettoyées par metaLine/safePageUrl.
 */
export function buildEditIssue(e: CleanEdit): GithubIssuePayload {
  const where = e.section ? `${e.pageTitle || e.pageUrl} › ${e.section}` : (e.pageTitle || e.pageUrl || 'page inconnue');
  const title = `[${e.editLabel}] ${metaLine(where, 120) || 'Édition contextuelle'}`;

  const contactLine = e.contact ? e.contact : '_(anonyme, pas de canal de réponse)_';
  const pageLink = e.pageUrl ? `\`${e.pageUrl}\`` : '_(non transmis)_';

  const parts: string[] = [
    `**Type :** ${e.editLabel}`,
    `**Page :** ${pageLink}`,
  ];
  if (e.pageTitle) parts.push(`**Titre :** ${metaLine(e.pageTitle, 200)}`);
  if (e.section) parts.push(`**Section :** ${metaLine(e.section, 200)}`);
  parts.push(`**Canal de contact :** ${contactLine}`);
  parts.push(`**Reçu le :** ${new Date().toISOString()}`);
  parts.push('', '---', '');

  // Passage cité (toujours présent).
  parts.push('### Passage concerné', '', fenceUntrusted(e.selection, LIMITS.selection), '');

  if (e.editKind === 'correction') {
    parts.push('### Correction proposée', '');
    parts.push('**Actuel :**', '', fenceUntrusted(e.before || e.selection, LIMITS.before), '');
    parts.push('**Proposé :**', '', fenceUntrusted(e.after, LIMITS.after), '');
    if (e.comment) parts.push('**Note :**', '', fenceUntrusted(e.comment, LIMITS.body), '');
  } else {
    const heading = e.editKind === 'source' ? 'Source / référence proposée'
      : e.editKind === 'factual' ? 'Erreur signalée'
      : 'Commentaire';
    parts.push(`### ${heading}`, '', fenceUntrusted(e.comment, LIMITS.body), '');
  }

  parts.push(
    '---',
    '',
    '> Édition contextuelle anonyme via le Mode contributeur du site.',
    '> Le passage cité provient du contenu de la page. Aucune IP ni métadonnée',
    '> client n\'est stockée. À relire avant toute reprise vers le dépôt public.',
  );

  return { title, body: parts.join('\n'), labels: ['dead-drop', 'edit', EDIT_LABEL[e.editKind]] };
}

/** Map type → label GitHub (à créer côté repo, sinon GitHub les crée à la volée). */
const TYPE_LABEL: Record<DropType, string> = {
  bug: 'bug',
  juridique: 'juridique',
  feature: 'feature',
};

/**
 * Construit le corps de l'Issue. Le contenu utilisateur est inséré tel quel
 * (Markdown accepté) MAIS isolé dans une section claire. On ne met PAS le corps
 * utilisateur dans le titre (seulement le type + un horodatage neutre), pour ne
 * pas exposer de contenu sensible dans les notifications/aperçus courts.
 */
export function buildIssue(d: CleanDrop): GithubIssuePayload {
  // Titre neutre et non identifiant : type + premiers mots nettoyés du corps.
  const snippet = oneLine(d.body).slice(0, 80);
  const title = `[${d.typeLabel}] ${snippet || 'Contribution anonyme'}`;

  const contactLine = d.contact
    ? d.contact
    : '_(anonyme, pas de canal de réponse)_';

  const body = [
    `**Type :** ${d.typeLabel}`,
    `**Canal de contact :** ${contactLine}`,
    `**Reçu le :** ${new Date().toISOString()}`,
    '',
    '---',
    '',
    '### Contenu de la contribution',
    '',
    d.body,
    '',
    '---',
    '',
    '> Soumission anonyme via la Boîte aux lettres morte (Dead Drop) du site.',
    '> Aucune IP ni métadonnée client n\'est stockée. À relire/anonymiser avant',
    '> toute reprise vers le dépôt public.',
  ].join('\n');

  return { title, body, labels: ['dead-drop', TYPE_LABEL[d.type]] };
}

// ── Labels GitHub : création idempotente avec couleurs ───────────────────────
// GitHub crée un label inconnu à la volée quand on l'assigne, mais en gris par
// défaut. Pour que ta file de modération soit lisible d'un coup d'œil, on s'assure
// (une seule fois par process) que les labels existent avec une couleur dédiée.
// L'opération est best-effort : si elle échoue, la création d'Issue continue
// (le label sera juste gris). On ne bloque jamais une contribution là-dessus.

const DROP_LABELS: Array<{ name: string; color: string; description: string }> = [
  { name: 'dead-drop',   color: '00ff9f', description: 'Reçu via la boîte aux lettres morte du site' },
  { name: 'edit',        color: '1f6feb', description: 'Édition contextuelle (sélection de passage)' },
  { name: 'bug',         color: 'd73a4a', description: 'Signalement de bug' },
  { name: 'juridique',   color: '8957e5', description: 'Apport ou question juridique' },
  { name: 'feature',     color: '0e8a16', description: 'Idée de fonctionnalité' },
  { name: 'correction',  color: 'fbca04', description: 'Correction de texte proposée' },
  { name: 'commentaire', color: 'c5def5', description: 'Commentaire / suggestion sur un passage' },
  { name: 'source',      color: '5319e7', description: 'Ajout de source / référence' },
  { name: 'factuel',     color: 'b60205', description: 'Signalement d\'erreur factuelle' },
];

// Garde-fou : on ne tente l'amorçage qu'une fois par cycle de vie du process.
let labelsEnsured = false;

async function ensureLabels(repo: string, token: string): Promise<void> {
  if (labelsEnsured) return;
  labelsEnsured = true; // on marque tout de suite : pas de double tentative concurrente
  const headers = {
    'Accept': 'application/vnd.github+json',
    'Authorization': `Bearer ${token}`,
    'User-Agent': 'SoundSystemHardening-DeadDrop',
    'X-GitHub-Api-Version': '2022-11-28',
    'Content-Type': 'application/json',
  };
  await Promise.all(DROP_LABELS.map(async (l) => {
    try {
      // 201 = créé ; 422 = existe déjà (les deux nous conviennent). On ne met PAS
      // à jour un label existant pour ne pas écraser une couleur que tu aurais changée.
      await fetch(`https://api.github.com/repos/${repo}/labels`, {
        method: 'POST', headers, body: JSON.stringify(l),
      });
    } catch {
      // Réseau ou quota : on ignore, le label restera gris au pire.
    }
  }));
}

// ── Création de l'Issue via l'API GitHub ─────────────────────────────────────

export interface CreateIssueResult {
  ok: boolean;
  error?: string;
  status?: number;
}

/**
 * Crée l'Issue sur le dépôt PRIVÉ configuré. Le token est lu au runtime et
 * n'est jamais renvoyé au client. On vise un repo dédié (GITHUB_DROP_REPO) et
 * un token dédié (GITHUB_DROP_TOKEN) pour cloisonner ce flux du reste.
 */
export async function createGithubIssue(payload: GithubIssuePayload): Promise<CreateIssueResult> {
  const repo = process.env.GITHUB_DROP_REPO || import.meta.env.GITHUB_DROP_REPO;
  const token = process.env.GITHUB_DROP_TOKEN || import.meta.env.GITHUB_DROP_TOKEN;

  if (!repo || !/^[\w.-]+\/[\w.-]+$/.test(repo)) {
    return { ok: false, error: 'GITHUB_DROP_REPO non configuré.' };
  }
  if (!token) {
    return { ok: false, error: 'GITHUB_DROP_TOKEN non configuré.' };
  }

  // Amorçage best-effort des labels colorés (une seule fois par process).
  await ensureLabels(repo, token);

  let res: Response;
  try {
    res = await fetch(`https://api.github.com/repos/${repo}/issues`, {
      method: 'POST',
      headers: {
        'Accept': 'application/vnd.github+json',
        'Authorization': `Bearer ${token}`,
        'User-Agent': 'SoundSystemHardening-DeadDrop',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
  } catch {
    return { ok: false, error: 'GitHub injoignable.' };
  }

  if (res.status === 201) return { ok: true, status: 201 };

  // On ne fuit pas le détail GitHub au client (peut révéler le nom du repo privé).
  return {
    ok: false,
    status: res.status,
    error: res.status === 401 || res.status === 403
      ? 'Jeton GitHub invalide ou permissions insuffisantes.'
      : res.status === 404
        ? 'Dépôt cible introuvable.'
        : `Échec création Issue (${res.status}).`,
  };
}
