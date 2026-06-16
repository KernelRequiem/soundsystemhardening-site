/**
 * /api/dead-drop, Boîte aux lettres morte (Dead Drop)
 *
 * Endpoint PUBLIC. Reçoit une contribution anonyme et la transforme en Issue
 * GitHub sur un dépôt PRIVÉ dédié. Aucune base de données, aucun stockage local,
 * aucune IP conservée. Le PAT GitHub vit côté serveur (process.env) et n'est
 * jamais exposé.
 *
 * Chaîne de défense (du moins coûteux au plus coûteux à franchir) :
 *   1. CSRF / Origin            → vérifiée par le middleware (POST /api/* hors auth)
 *   2. Rate-limit global         → middleware (8 POST/10min/IP, toutes routes)
 *   3. Honeypot                  → champ caché 'website' rempli ⇒ faux OK silencieux
 *   4. Proof-of-work             → coût CPU client, challenge signé anti-rejeu
 *   5. Rate-limit DÉDIÉ          → 3 soumissions acceptées/10min/IP (anti-flood PAT)
 *   6. Validation / taille       → type connu, corps non vide, limites strictes
 *   7. Anti-rejeu du challenge   → un prefix résolu n'est consommable qu'une fois
 *
 * On répond volontairement de façon neutre : on ne distingue pas honeypot/bot
 * d'un succès réel (pas d'information exploitable pour un attaquant).
 */
import type { APIRoute } from 'astro';
import { publicOrigin } from '../../lib/origins';
import {
  verifySolution,
  consumeChallengeOnce,
  isDropRateLimited,
  recordDropHit,
  validateDrop,
  validateEdit,
  buildIssue,
  buildEditIssue,
  createGithubIssue,
  type PowSolution,
  type GithubIssuePayload,
} from '../../lib/deadDrop';

export const prerender = false;

const ORIGIN = publicOrigin();
const cors = {
  'Access-Control-Allow-Origin': ORIGIN,
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
} as const;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...cors },
  });
}

/**
 * IP cliente. Même logique que le middleware : on privilégie l'adresse réelle de
 * la connexion (non falsifiable) ; X-Forwarded-For en repli seulement.
 * NB : l'IP sert UNIQUEMENT au rate-limit en mémoire, elle n'est jamais stockée
 * ni jointe à l'Issue.
 */
function clientIp(clientAddress: string | undefined, request: Request): string {
  if (clientAddress) return clientAddress;
  const xff = request.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0].trim();
  return 'unknown';
}

export const POST: APIRoute = async ({ request, clientAddress }) => {
  // ── Parse du corps (JSON attendu) ───────────────────────────────────────────
  let data: Record<string, unknown> = {};
  try {
    const ct = request.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await request.json();
    } else {
      new URLSearchParams(await request.text()).forEach((v, k) => { data[k] = v; });
    }
  } catch {
    return json({ ok: false, error: 'Corps invalide.' }, 400);
  }

  // ── Honeypot ────────────────────────────────────────────────────────────────
  // Champ 'website' caché en CSS, invisible pour un humain. Rempli ⇒ bot. On
  // renvoie un faux succès : le bot croit avoir réussi et n'insiste pas, aucune
  // Issue n'est créée.
  if (typeof data.website === 'string' && data.website.trim() !== '') {
    return json({ ok: true });
  }

  // ── Proof-of-work ───────────────────────────────────────────────────────────
  const pow = data.pow as PowSolution | undefined;
  if (!pow) return json({ ok: false, error: 'Preuve de travail manquante.' }, 400);
  const powCheck = verifySolution(pow);
  if (!powCheck.ok) return json({ ok: false, error: powCheck.error }, 400);

  // Anti-rejeu : ce challenge précis ne peut servir qu'une fois.
  if (!consumeChallengeOnce(pow.prefix)) {
    return json({ ok: false, error: 'Preuve déjà utilisée, recharge la page.' }, 409);
  }

  // ── Rate-limit dédié ────────────────────────────────────────────────────────
  const ip = clientIp(clientAddress, request);
  if (isDropRateLimited(ip)) {
    return json({ ok: false, error: 'Trop de soumissions. Réessaie dans quelques minutes.' }, 429);
  }

  // ── Validation / sanitisation ───────────────────────────────────────────────
  // Deux modes : 'edit' (édition contextuelle sur une sélection) ou défaut
  // (soumission libre). On route selon le champ 'mode'. Dans les deux cas, la
  // sanitisation du contenu non fiable est faite côté lib (fenceUntrusted, etc.).
  let issue: GithubIssuePayload;
  if (data.mode === 'edit') {
    const ve = validateEdit({
      editKind: data.editKind,
      pageUrl: data.pageUrl,
      pageTitle: data.pageTitle,
      section: data.section,
      selection: data.selection,
      before: data.before,
      after: data.after,
      comment: data.comment,
      contact: data.contact,
    });
    if (!ve.ok || !ve.data) return json({ ok: false, error: ve.error }, 400);
    issue = buildEditIssue(ve.data);
  } else {
    const v = validateDrop({ type: data.type, body: data.body, contact: data.contact });
    if (!v.ok || !v.data) return json({ ok: false, error: v.error }, 400);
    issue = buildIssue(v.data);
  }

  // ── Création de l'Issue GitHub ──────────────────────────────────────────────
  const created = await createGithubIssue(issue);
  if (!created.ok) {
    // On NE consomme PAS le quota de rate-limit en cas d'échec serveur (le
    // contributeur n'est pas responsable d'une mauvaise config ou d'un GitHub down).
    return json({ ok: false, error: created.error || 'Échec de l\'envoi.' }, created.status === 404 || created.status === 401 || created.status === 403 ? 500 : 502);
  }

  // Succès : on décompte enfin la soumission pour le rate-limit dédié.
  recordDropHit(ip);
  return json({ ok: true });
};

export const OPTIONS: APIRoute = () => new Response(null, { status: 204, headers: cors });
export const GET: APIRoute = () => new Response(null, { status: 405 });
