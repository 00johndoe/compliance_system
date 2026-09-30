import { readFileSync } from 'node:fs';

// A stored assessment shaped exactly like assessment.html writes it (values 0 / 2.5 / 5).
// Built from the real requirements dataset so field ids always match: a personal-data processor
// (Tier 1A + 1B = 20 requirements in three groups). Group scores: Incident reporting & response 17%,
// Data protection principles 75%, Security safeguards & risk 40%; ISO Organizational 50, People 100,
// Physical 50, Technological 50.
const DATA = JSON.parse(readFileSync(new URL('../../data/ghana-requirements.json', import.meta.url), 'utf8'));
const ANSWERS = {
  'T1A-01': 2.5, 'T1A-02': 0, 'T1B-16': 0,
  'T1B-01': 5, 'T1B-02': 5, 'T1B-03': 5, 'T1B-04': 5, 'T1B-05': 5, 'T1B-06': 5,
  'T1B-07': 2.5, 'T1B-08': 2.5, 'T1B-09': 2.5, 'T1B-10': 2.5, 'T1B-17': 2.5, 'T1B-18': 2.5,
  'T1B-11': 5, 'T1B-12': 2.5, 'T1B-13': 2.5, 'T1B-14': 0, 'T1B-15': 0,
};
const ncf = {}, requirements = {};
for (const g of DATA.groups) {
  DATA.requirements.filter((r) => r.group === g.id).forEach((r, i) => {
    if (r.id in ANSWERS) { ncf['ncf_' + g.name.replace(/\s+/g, '_') + '_' + i] = ANSWERS[r.id]; requirements[r.id] = ANSWERS[r.id]; }
  });
}
export const SEED = {
  organization: { name: 'Accra Test Bank', sector: 'Financial Services', size: 'Medium (51-250)', email: 'test@example.com' },
  applicability: { personalData: true, ciiOwner: false },
  ncf, requirements,
  iso: {
    'iso_Organizational_Controls_0': 5, 'iso_Organizational_Controls_1': 2.5, 'iso_Organizational_Controls_2': 0,
    'iso_People_Controls_0': 5, 'iso_Physical_Controls_0': 2.5,
    'iso_Technological_Controls_0': 0, 'iso_Technological_Controls_1': 5,
  },
  timestamp: '2026-09-01T10:00:00.000Z',
};

export const MAIN_PAGES = ['index', 'mapping', 'assessment', 'gaps', 'actions'];
export const ALL_PAGES = [...MAIN_PAGES, 'results', 'results-print'];
