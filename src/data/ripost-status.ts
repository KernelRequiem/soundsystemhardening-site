// ════════════════════════════════════════════════════════════════════════
// STATUT DE LA LOI RIPOST : SOURCE UNIQUE DE VÉRITÉ
// ════════════════════════════════════════════════════════════════════════
// Toutes les pages qui affichent l'état d'avancement de RIPOST lisent CE fichier.
// Pour mettre à jour le site quand la loi évolue : modifier UNIQUEMENT ici.
//
// Procédure de mise à jour (à chaque vérification) :
//   1. Vérifier l'état réel sur les sources officielles :
//      - https://www.assemblee-nationale.fr (dossier législatif / navette)
//      - https://www.senat.fr
//      - https://www.legifrance.gouv.fr (promulgation)
//   2. Mettre à jour `lastChecked` (date du jour).
//   3. Si l'étape a changé : ajuster `inForce`, `currentStage`, et la liste `timeline`.
//   4. Commit + push : les 3 pages (ripost, Strategie-contre-ripost, strategie)
//      se mettent à jour automatiquement.

export interface RipostStatus {
  /** La loi est-elle promulguée et applicable ? */
  inForce: boolean;
  /** Résumé de l'étape actuelle (1 phrase). */
  currentStage: string;
  /** Date de dernière vérification du statut (format lisible FR). */
  lastChecked: string;
  /** Phrase courte sur ce qui s'applique aujourd'hui (droit en vigueur). */
  currentLaw: string;
  /** Étapes franchies / à venir de la navette parlementaire. */
  timeline: { date: string; label: string; done: boolean }[];
}

export const ripostStatus: RipostStatus = {
  inForce: false,
  currentStage: "Adopté au Sénat le 26 mai 2026 (243 pour / 33 contre). Retourne à l'Assemblée nationale (été / rentrée 2026).",
  lastChecked: '16 juin 2026',
  currentLaw:
    "Le droit actuel s'applique : participer à une free party reste légal. Seuls les organisateurs risquent une contravention (1 500 €).",
  timeline: [
    { date: '9 avril 2026', label: "PPL 1133 adoptée à l'Assemblée nationale (78 / 67)", done: true },
    { date: '26 mai 2026', label: 'RIPOST adopté au Sénat (243 / 33)', done: true },
    { date: 'Été / rentrée 2026', label: "Réexamen à l'Assemblée nationale", done: false },
    { date: 'À venir', label: 'Promulgation (entrée en vigueur)', done: false },
  ],
};

// Peines prévues PAR le texte RIPOST (si adopté), source unique pour les comparatifs.
export const ripostPenalties = {
  participation: { afd: 'AFD 1 500 €', tribunal: '6 mois + 7 500 € au tribunal' },
  organisation: { peine: '2 ans + 30 000 €', nature: 'délit pénal' },
  seuilDeclaration: '250 personnes',
};

// Droit ACTUEL (avant RIPOST), pour les comparatifs avant/après.
export const currentLawFacts = {
  participation: 'Légale',
  organisation: '1 500 €',
  seuilDeclaration: '500 personnes',
};
