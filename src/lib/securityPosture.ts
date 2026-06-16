/**
 * securityPosture.ts, Posture défensive de l'infra (vue admin SSR)
 *
 * Complète monitoring.ts. Même principe : importé directement par la page admin,
 * jamais exposé en endpoint public, aucun secret rendu (présence/absence ou
 * verdict, jamais la valeur). Calculé à la demande.
 *
 * IMPORTANT, sur l'honnêteté des indicateurs : une appli ne peut PAS s'auto-scanner
 * ses ports comme le ferait un attaquant externe (elle tourne à l'intérieur de son
 * propre périmètre). On distingue donc trois niveaux de fiabilité :
 *   - MESURÉ : vérifié en direct par le process (en-têtes via self-fetch, expiry TLS).
 *   - DÉRIVÉ : déduit du journal de sécurité en mémoire (tentatives d'intrusion).
 *   - EXTERNE : nécessite une sonde indépendante ; affiché "non configuré" tant qu'absent.
 * Mentir sur ce niveau donnerait un faux sentiment de sécurité, pire que rien.
 */

import { getSecuritySnapshot, countRecent, type SecurityEvent } from './securityLog';

const APEX = 'https://soundsystemhardening.fr';

// Niveau de confiance d'un indicateur (cf. en-tête de fichier).
export type PostureSource = 'mesure' | 'derive' | 'externe';
export type PostureStatus = 'ok' | 'warn' | 'bad' | 'unknown';

export interface PostureCheck {
  key:    string;
  label:  string;
  status: PostureStatus;
  value:  string;          // verdict lisible, jamais un secret
  source: PostureSource;
  hint?:  string;          // conseil de remédiation si status != ok
}

// ── 1. Posture HTTP (MESURÉ) ──────────────────────────────────────────
// On refait une requête sur notre propre URL publique et on inspecte les
// en-têtes de sécurité réellement servis EN SORTIE (telle que reçue par le visiteur).
// C'est le seul moyen fiable de savoir ce qu'un visiteur reçoit vraiment, par
// opposition à ce que le middleware croit poser.
interface HeaderRule {
  header:   string;
  label:    string;
  required: boolean;
  test:     (v: string | null) => PostureStatus;
  hint:     string;
}

const HEADER_RULES: HeaderRule[] = [
  {
    header: 'strict-transport-security', label: 'HSTS', required: true,
    test: (v) => !v ? 'bad' : /max-age=(\d+)/.test(v) && Number(RegExp.$1) >= 15552000 ? 'ok' : 'warn',
    hint: 'Forcer HTTPS durablement : max-age >= 6 mois, includeSubDomains, preload.',
  },
  {
    header: 'content-security-policy', label: 'CSP', required: true,
    test: (v) => !v ? 'bad' : /default-src/.test(v) && /frame-ancestors/.test(v) ? 'ok' : 'warn',
    hint: 'Limite les sources de scripts/cadres. Doit contenir default-src et frame-ancestors.',
  },
  {
    header: 'x-frame-options', label: 'X-Frame-Options', required: true,
    test: (v) => !v ? 'warn' : /deny|sameorigin/i.test(v) ? 'ok' : 'warn',
    hint: 'Anti-clickjacking. Doit être DENY (la CSP frame-ancestors prend le relais).',
  },
  {
    header: 'x-content-type-options', label: 'X-Content-Type-Options', required: true,
    test: (v) => v && /nosniff/i.test(v) ? 'ok' : 'warn',
    hint: 'Empêche le MIME-sniffing. Doit valoir nosniff.',
  },
  {
    header: 'referrer-policy', label: 'Referrer-Policy', required: true,
    test: (v) => v && /no-referrer|strict-origin/i.test(v) ? 'ok' : 'warn',
    hint: 'Évite la fuite d’URL interne vers les sites tiers. Idéal : no-referrer.',
  },
  {
    header: 'permissions-policy', label: 'Permissions-Policy', required: false,
    test: (v) => v ? 'ok' : 'warn',
    hint: 'Désactive les API sensibles (caméra, micro, géoloc) non utilisées.',
  },
  {
    header: 'server', label: 'En-tête Server', required: false,
    // Ici "ok" = absence ou valeur peu bavarde (on ne veut PAS divulguer la version).
    test: (v) => !v ? 'ok' : /\d+\.\d+/.test(v) ? 'warn' : 'ok',
    hint: 'Ne pas divulguer le logiciel/version serveur (réduit le ciblage d’exploits).',
  },
];

export interface HttpPosture {
  reachable:  boolean;
  httpStatus: number | null;
  redirectsHttp: PostureStatus;   // 80 -> 443 ?
  checks:     PostureCheck[];
  score:      { ok: number; total: number };
  checkedAt:  string;
  error?:     string;
}

async function fetchHeaders(url: string, opts: RequestInit = {}): Promise<{ status: number; headers: Headers } | null> {
  try {
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), 5000);
    const res = await fetch(url, { redirect: 'manual', signal: ctrl.signal, ...opts });
    clearTimeout(to);
    return { status: res.status, headers: res.headers };
  } catch {
    return null;
  }
}

export async function getHttpPosture(): Promise<HttpPosture> {
  const checkedAt = new Date().toISOString();
  const https = await fetchHeaders(APEX, { method: 'GET', headers: { 'user-agent': 'HardeningCore-SelfCheck' } });

  if (!https) {
    return {
      reachable: false, httpStatus: null, redirectsHttp: 'unknown',
      checks: [], score: { ok: 0, total: 0 }, checkedAt,
      error: 'Apex injoignable depuis l'application (réseau sortant ou DNS).',
    };
  }

  const checks: PostureCheck[] = HEADER_RULES.map((rule) => {
    const raw = https.headers.get(rule.header);
    const status = rule.test(raw);
    return {
      key: rule.header, label: rule.label, status, source: 'mesure',
      value: rule.header === 'server' && raw
        ? (status === 'warn' ? 'version divulguée' : 'discret')
        : raw ? 'présent' : 'absent',
      hint: status === 'ok' ? undefined : rule.hint,
    };
  });

  // Test de la redirection HTTP -> HTTPS (un attaquant ne doit pas pouvoir rester en clair).
  const http = await fetchHeaders('http://soundsystemhardening.fr', { method: 'HEAD' });
  let redirectsHttp: PostureStatus = 'unknown';
  if (http) {
    const loc = http.headers.get('location') || '';
    redirectsHttp = (http.status >= 300 && http.status < 400 && /^https:/i.test(loc)) ? 'ok' : 'bad';
  }

  const ok = checks.filter((c) => c.status === 'ok').length;
  return {
    reachable: true, httpStatus: https.status, redirectsHttp,
    checks, score: { ok, total: checks.length }, checkedAt,
  };
}

// ── 2. Certificat TLS (MESURÉ) ────────────────────────────────────────
// Jours restants avant expiration du certificat servi sur 443. On ouvre une
// connexion TLS et on lit le certificat de pair. <15j = warn, <5j = bad.
export interface TlsPosture {
  available:    boolean;
  validTo:      string | null;
  daysLeft:     number | null;
  issuer:       string | null;
  status:       PostureStatus;
  error?:       string;
}

export async function getTlsPosture(): Promise<TlsPosture> {
  try {
    const tls = await import('tls');
    return await new Promise<TlsPosture>((resolve) => {
      const socket = tls.connect(
        { host: 'soundsystemhardening.fr', port: 443, servername: 'soundsystemhardening.fr', timeout: 5000 },
        () => {
          const cert = socket.getPeerCertificate();
          socket.end();
          if (!cert || !cert.valid_to) {
            return resolve({ available: false, validTo: null, daysLeft: null, issuer: null, status: 'unknown', error: 'Certificat illisible.' });
          }
          const validTo = new Date(cert.valid_to);
          const daysLeft = Math.floor((validTo.getTime() - Date.now()) / 86400000);
          const status: PostureStatus = daysLeft < 5 ? 'bad' : daysLeft < 15 ? 'warn' : 'ok';
          const issuer = cert.issuer && (cert.issuer.O || cert.issuer.CN) ? String(cert.issuer.O || cert.issuer.CN) : null;
          resolve({ available: true, validTo: validTo.toISOString(), daysLeft, issuer, status });
        },
      );
      socket.on('error', () => resolve({ available: false, validTo: null, daysLeft: null, issuer: null, status: 'unknown', error: 'Connexion TLS impossible depuis l'application.' }));
      socket.on('timeout', () => { socket.destroy(); resolve({ available: false, validTo: null, daysLeft: null, issuer: null, status: 'unknown', error: 'Timeout TLS.' }); });
    });
  } catch {
    return { available: false, validTo: null, daysLeft: null, issuer: null, status: 'unknown', error: 'Module TLS indisponible.' };
  }
}

// ── 3. Tentatives d'intrusion (DÉRIVÉ du journal mémoire) ─────────────
// On ne "scanne" rien : on lit les évènements déjà enregistrés par le middleware.
// Heuristiques simples et explicables (pas de boîte noire).
export interface IntrusionSignal {
  key:    string;
  label:  string;
  count:  number;        // sur la fenêtre
  windowLabel: string;
  status: PostureStatus;
  detail: string;
}

export interface IntrusionPosture {
  windowMin:  number;
  signals:    IntrusionSignal[];
  topSources: Array<{ ip: string; count: number; types: string }>;   // IP anonymisées (préfixe /24)
  bootTs:     number;
}

const MIN = 60_000;

export function getIntrusionPosture(): IntrusionPosture {
  const snap = getSecuritySnapshot(500);
  const win = 15;
  const winMs = win * MIN;

  // 404/route inconnue répétés = balayage de répertoires (dir-busting).
  const badReq = countRecent('bad_request', winMs);
  // Accès refusés à /hardeningcore = quelqu'un sonde la console d'admin.
  const terrain = countRecent('terrain_denied', winMs);
  // Échecs de login en série = brute-force / credential stuffing.
  const loginKo = countRecent('login_failure', winMs);
  // 429 = quelqu'un tape assez fort pour déclencher le rate-limit.
  const rate = countRecent('rate_limit', winMs);
  // Rejets CSRF = POST cross-origin, souvent automatisé.
  const csrf = countRecent('csrf_reject', winMs);

  const signals: IntrusionSignal[] = [
    { key: 'dirbust', label: 'Balayage de routes (404/URI invalides)', count: badReq, windowLabel: `${win}m`,
      status: badReq > 30 ? 'bad' : badReq > 8 ? 'warn' : 'ok',
      detail: 'Pic = énumération de répertoires (gobuster, nikto…).' },
    { key: 'admin_probe', label: 'Sondage de la console admin', count: terrain, windowLabel: `${win}m`,
      status: terrain > 15 ? 'bad' : terrain > 4 ? 'warn' : 'ok',
      detail: 'Accès /hardeningcore sans session : tentative de trouver l’admin.' },
    { key: 'bruteforce', label: 'Brute-force / bourrage d’identifiants', count: loginKo, windowLabel: `${win}m`,
      status: loginKo > 12 ? 'bad' : loginKo > 4 ? 'warn' : 'ok',
      detail: 'Échecs de login répétés depuis la même source.' },
    { key: 'ratelimit', label: 'Seuil de débit franchi (429)', count: rate, windowLabel: `${win}m`,
      status: rate > 20 ? 'bad' : rate > 5 ? 'warn' : 'ok',
      detail: 'Le rate-limit a mordu : trafic anormalement intense.' },
    { key: 'csrf', label: 'POST cross-origin rejetés (CSRF)', count: csrf, windowLabel: `${win}m`,
      status: csrf > 10 ? 'bad' : csrf > 2 ? 'warn' : 'ok',
      detail: 'Requêtes POST d’une origine non autorisée.' },
  ];

  // Top des IP (préfixes) les plus actives sur les évènements "négatifs".
  const negative = new Set(['bad_request', 'terrain_denied', 'login_failure', 'rate_limit', 'csrf_reject']);
  const byIp = new Map<string, { count: number; types: Set<string> }>();
  for (const e of snap.recent as SecurityEvent[]) {
    if (!negative.has(e.type)) continue;
    const cur = byIp.get(e.ip) || { count: 0, types: new Set<string>() };
    cur.count += 1; cur.types.add(e.type);
    byIp.set(e.ip, cur);
  }
  const topSources = [...byIp.entries()]
    .map(([ip, v]) => ({ ip, count: v.count, types: [...v.types].join(', ') }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  return { windowMin: win, signals, topSources, bootTs: snap.bootTs };
}

// ── 4. Scan de ports externe (EXTERNE, sonde requise) ─────────────────
// Honnête par construction : l'app ne peut pas voir ses ports comme l'extérieur.
// On lit le résultat d'une sonde externe indépendante si elle a déposé un fichier ; sinon
// on affiche clairement "non configuré". Aucune simulation, aucun faux vert.
export interface PortScanPosture {
  configured: boolean;
  scannedAt:  string | null;
  source:     string | null;             // ex: "GitHub Action nmap", "monit externe"
  openPorts:  Array<{ port: number; service: string; expected: boolean }>;
  unexpected: number;
  note:       string;
}

export function getPortScanPosture(): PortScanPosture {
  // Convention : une sonde externe peut déposer private/portscan-latest.json
  //   { scannedAt, source, openPorts:[{port, service, expected}] }
  // Tant qu'il n'existe pas, on l'affiche honnêtement comme non configuré.
  try {
    const { readFileSync, existsSync } = require('fs') as typeof import('fs');
    const { join } = require('path') as typeof import('path');
    const file = join(process.cwd(), 'private', 'portscan-latest.json');
    if (!existsSync(file)) {
      return {
        configured: false, scannedAt: null, source: null, openPorts: [], unexpected: 0,
        note: 'Aucune sonde externe configurée. Un vrai scan de ports doit venir d\'une source indépendante, hors du périmètre du serveur (cf. note ci-dessous).',
      };
    }
    const data = JSON.parse(readFileSync(file, 'utf-8'));
    const openPorts: PortScanPosture['openPorts'] = Array.isArray(data.openPorts) ? data.openPorts : [];
    const unexpected = openPorts.filter((p) => !p.expected).length;
    return {
      configured: true,
      scannedAt: data.scannedAt || null,
      source: data.source || 'inconnue',
      openPorts,
      unexpected,
      note: unexpected > 0
        ? `${unexpected} port(s) ouvert(s) inattendu(s) : surface à fermer.`
        : 'Seuls les ports attendus (80/443) sont exposés.',
    };
  } catch {
    return {
      configured: false, scannedAt: null, source: null, openPorts: [], unexpected: 0,
      note: 'Lecture de la sonde externe impossible.',
    };
  }
}

// ── Agrégat posture ───────────────────────────────────────────────────
export interface SecurityPosture {
  http:      HttpPosture;
  tls:       TlsPosture;
  intrusion: IntrusionPosture;
  ports:     PortScanPosture;
}

export async function getSecurityPosture(): Promise<SecurityPosture> {
  // http et tls sont des I/O réseau : on les lance en parallèle.
  const [http, tls] = await Promise.all([getHttpPosture(), getTlsPosture()]);
  return { http, tls, intrusion: getIntrusionPosture(), ports: getPortScanPosture() };
}
