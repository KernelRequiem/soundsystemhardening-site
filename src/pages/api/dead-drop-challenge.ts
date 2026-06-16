/**
 * /api/dead-drop-challenge, Émission d'un challenge proof-of-work
 *
 * GET public. Renvoie un challenge signé (prefix + ts + bits + sig) que le client
 * doit résoudre avant de pouvoir soumettre une contribution sur /api/dead-drop.
 *
 * Le challenge est signé côté serveur (HMAC) : il n'y a aucun état à stocker, et
 * le client ne peut pas en forger un. Le rate-limit générique du middleware ne
 * s'applique pas au GET (il ne vise que les POST /api/*), ce qui est voulu : émettre
 * un challenge ne consomme pas le PAT et ne crée rien. Le coût est reporté sur le
 * POST réel, lui rate-limité.
 */
import type { APIRoute } from 'astro';
import { issueChallenge } from '../../lib/deadDrop';
import { publicOrigin } from '../../lib/origins';

export const prerender = false;

export const GET: APIRoute = () => {
  const challenge = issueChallenge();
  return new Response(JSON.stringify(challenge), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Access-Control-Allow-Origin': publicOrigin(),
    },
  });
};

// Toute autre méthode est refusée.
export const POST: APIRoute = () => new Response(null, { status: 405 });
