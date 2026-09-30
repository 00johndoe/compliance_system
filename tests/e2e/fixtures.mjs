// A stored assessment shaped exactly like assessment.html writes it (values 0 / 2.5 / 5).
export const SEED = {
  organization: { name: 'Accra Test Bank', sector: 'Financial Services', size: 'Medium (51-250)', email: 'test@example.com' },
  ncf: {
    'ncf_Governance_&_Leadership_0': 5, 'ncf_Governance_&_Leadership_1': 2.5,
    'ncf_Legal_&_Regulatory_0': 0, 'ncf_Legal_&_Regulatory_1': 5,
    'ncf_Incident_Response_0': 2.5, 'ncf_Incident_Response_1': 0,
    'ncf_Critical_Infrastructure_0': 5,
    'ncf_Capacity_Building_0': 2.5, 'ncf_Capacity_Building_1': 0,
    'ncf_International_Cooperation_0': 5,
  },
  iso: {
    'iso_Organizational_Controls_0': 5, 'iso_Organizational_Controls_1': 2.5, 'iso_Organizational_Controls_2': 0,
    'iso_People_Controls_0': 5, 'iso_Physical_Controls_0': 2.5,
    'iso_Technological_Controls_0': 0, 'iso_Technological_Controls_1': 5,
  },
  timestamp: '2026-09-01T10:00:00.000Z',
};

export const MAIN_PAGES = ['index', 'mapping', 'assessment', 'gaps'];
export const ALL_PAGES = [...MAIN_PAGES, 'results', 'results-print'];
