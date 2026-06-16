/**
 * /api/spots/search, Recherche de spots candidats (proxy base de données, admin/modérateur)
 *
 * POST { categories?, minResidential?, minPolice?, maxRoad?, minIsolement?,
 *        minArea?, centerLat?, centerLng?, radiusM?, limit?, offset? }
 *
 * Le navigateur (SpotCheck, derrière l'auth) appelle cet endpoint ; le serveur
 * interroge la base de données via les fonctions RPC search_spots/count_spots.
 * La clé ne quitte jamais le serveur (architecture proxy).
 */
import type { APIRoute } from 'astro';
import { checkAdminAuth } from '../../../lib/adminAuth';
import { can } from '../../../lib/permissions';
import { isTrustedAdminOrigin } from '../../../lib/origins';
import { rpc, supabaseConfigured } from '../../../lib/supabase';

export const prerender = false;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

// Catégories autorisées (doivent matcher le CHECK de candidate_spots.category).
const CATS = new Set(['industriel', 'friche', 'carriere', 'terrain', 'autre']);

function num(v: unknown, min: number, max: number): number | null {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  return Math.min(max, Math.max(min, n));
}

export const POST: APIRoute = async ({ request, cookies }) => {
  const auth = checkAdminAuth(cookies);
  if (!auth.valid || !auth.email) return json({ ok: false, error: 'Non autorisé.' }, 401);
  // SpotCheck est un outil interne : on exige la permission d'usage.
  if (!can(auth.role, 'spotcheck.use')) return json({ ok: false, error: 'Permission refusée.' }, 403);
  if (!isTrustedAdminOrigin(request.headers.get('origin'))) {
    return json({ ok: false, error: 'Origine non autorisée.' }, 403);
  }
  if (!supabaseConfigured()) {
    return json({ ok: false, error: 'Recherche indisponible : base de données non configurée.' }, 503);
  }

  let body: Record<string, unknown>;
  try { body = await request.json(); } catch { return json({ ok: false, error: 'JSON invalide.' }, 400); }

  // Validation/normalisation des filtres.
  let categories: string[] | null = null;
  if (Array.isArray(body.categories)) {
    categories = body.categories.map(String).filter((c) => CATS.has(c));
    if (categories.length === 0) categories = null;
  }
  const args = {
    p_categories:      categories,
    p_min_residential: num(body.minResidential, 0, 100000),
    p_min_police:      num(body.minPolice, 0, 100000),
    p_max_road:        num(body.maxRoad, 0, 100000),
    p_min_isolement:   num(body.minIsolement, 0, 10),
    p_min_area:        num(body.minArea, 0, 100000000),
    p_center_lat:      num(body.centerLat, -90, 90),
    p_center_lng:      num(body.centerLng, -180, 180),
    p_radius_m:        num(body.radiusM, 0, 2000000),
    p_limit:           num(body.limit, 1, 1000) ?? 200,
    p_offset:          num(body.offset, 0, 1000000) ?? 0,
  };

  // Recherche + comptage (deux RPC, en parallèle).
  const countArgs = { ...args }; delete (countArgs as Record<string, unknown>).p_limit; delete (countArgs as Record<string, unknown>).p_offset;
  const [res, cnt] = await Promise.all([
    rpc<unknown[]>('search_spots', args),
    rpc<number>('count_spots', countArgs),
  ]);

  if (!res.ok) return json({ ok: false, error: res.error }, res.status);
  return json({ ok: true, results: res.data ?? [], total: cnt.ok ? cnt.data : null });
};

export const GET: APIRoute = () => new Response(null, { status: 405 });
