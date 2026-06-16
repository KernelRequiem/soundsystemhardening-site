/**
 * supabase.ts, Accès serveur à la base de données externe (API REST PostgREST) sans SDK
 *
 * On appelle l'API REST directement en fetch côté serveur, plutôt que d'embarquer
 * un SDK : moins de dépendances, et la clé reste exclusivement côté serveur
 * (architecture proxy, le navigateur ne parle jamais à la base directement, il
 * passe par nos endpoints /api/spots/*).
 *
 * Variables d'environnement (production) :
 *   SUPABASE_URL          = URL de l'API REST (sans /rest/v1)
 *   SUPABASE_ANON_KEY     = clé de lecture (RLS appliqué)
 *   SUPABASE_SERVICE_KEY  = clé d'écriture (bypass RLS), extraction uniquement,
 *                           jamais nécessaire pour les lectures de l'app.
 */

function baseUrl(): string {
  const u = process.env.SUPABASE_URL || import.meta.env.SUPABASE_URL || '';
  return u.replace(/\/+$/, '').replace(/\/rest\/v1$/, '');
}
function anonKey(): string {
  return process.env.SUPABASE_ANON_KEY || import.meta.env.SUPABASE_ANON_KEY || '';
}

export function supabaseConfigured(): boolean {
  return !!baseUrl() && !!anonKey();
}

/** Appel d'une fonction RPC Postgres (ex: search_spots) en lecture. */
export async function rpc<T = unknown>(
  fn: string, args: Record<string, unknown>,
): Promise<{ ok: boolean; data?: T; error?: string; status: number }> {
  const url = `${baseUrl()}/rest/v1/rpc/${encodeURIComponent(fn)}`;
  const key = anonKey();
  if (!baseUrl() || !key) return { ok: false, error: 'Base de données non configurée.', status: 503 };
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: {
        'apikey': key,
        'Authorization': `Bearer ${key}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(args),
    });
    if (!r.ok) {
      const txt = await r.text().catch(() => '');
      return { ok: false, error: `Base de données ${r.status}: ${txt.slice(0, 200)}`, status: r.status };
    }
    const data = (await r.json()) as T;
    return { ok: true, data, status: 200 };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'Base de données indisponible.', status: 502 };
  }
}
