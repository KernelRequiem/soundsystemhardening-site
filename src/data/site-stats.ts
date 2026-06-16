// ════════════════════════════════════════════════════════════════════════
// AGRÉGATS DU SITE : calculés à partir des données centralisées de src/data/
// ════════════════════════════════════════════════════════════════════════
// Source unique des chiffres affichés (baromètre /actu, etc.). Tout est dérivé
// des fichiers de données réels : aucun chiffre saisi à la main, donc toujours
// cohérent avec le contenu. Recalculé au build (site statique).

import incidents from './incidents.json';
import { listWikiSlugs } from '../lib/wikiPages';
import { ripostStatus } from './ripost-status';

type Incident = {
  id: string; lieu: string; date: string; type: string; titre: string;
  departement?: string; type_operation?: string;
};

const all = incidents as Incident[];

// Tri par date décroissante (les plus récents d'abord)
const byDateDesc = [...all].sort((a, b) => (a.date < b.date ? 1 : -1));

// Départements distincts touchés
const departments = new Set(all.map((i) => i.departement).filter(Boolean));

// Répartition par type (pour trouver le plus fréquent)
const typeCounts = all.reduce<Record<string, number>>((acc, i) => {
  acc[i.type] = (acc[i.type] || 0) + 1;
  return acc;
}, {});
const topType = Object.entries(typeCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '';

export const siteStats = {
  // Incidents
  incidentsTotal: all.length,
  departmentsTouched: departments.size,
  topIncidentType: topType,
  latestIncidentDate: byDateDesc[0]?.date ?? '',
  recentIncidents: byDateDesc.slice(0, 5).map((i) => ({
    date: i.date,
    lieu: i.lieu,
    titre: i.titre,
    type: i.type,
  })),

  // Wiki
  wikiPages: listWikiSlugs().length,

  // Statut RIPOST (réexporté pour un point d'accès unique au baromètre)
  ripost: {
    inForce: ripostStatus.inForce,
    stage: ripostStatus.currentStage,
    lastChecked: ripostStatus.lastChecked,
  },
};

// Étiquettes lisibles des types d'incident (pour l'affichage)
export const incidentTypeLabels: Record<string, string> = {
  charge: 'Charge / intervention',
  blessure: 'Blessure',
  saisie: 'Saisie de matériel',
  gav: 'GAV / interpellation',
  interdiction: 'Interdiction préfect.',
  autre: 'Autre',
};
