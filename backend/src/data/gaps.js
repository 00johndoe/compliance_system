'use strict';

/**
 * Gap analysis reference data between Ghana NCF and ISO/IEC 27002:2022.
 * Ported from server.py GAP_ANALYSIS.
 */
const GAP_ANALYSIS = {
  ghana_unique: [
    { control: 'GOV-02', title: 'National Cybersecurity Strategy Alignment', reason: "Specific to Ghana's national policy; no direct ISO equivalent." },
    { control: 'RISK-02', title: 'Threat Intelligence from Ghana CERT', reason: 'Ghana-specific threat intelligence source.' },
    { control: 'RISK-06', title: 'Critical National Infrastructure Risk', reason: 'National infrastructure focus beyond ISO scope.' },
    { control: 'RESP-02', title: 'Reporting to Cyber Security Authority', reason: 'Ghana-specific regulatory reporting requirement.' },
    { control: 'CAP-04', title: 'Local Talent Pipeline', reason: 'National capacity building not in ISO scope.' },
  ],
  iso_unique: [
    { control: '5.3', title: 'Segregation of Duties', reason: 'Detailed control not explicitly in Ghana NCF.' },
    { control: '5.9', title: 'Inventory of Information and Other Assets', reason: 'Asset inventory not explicitly addressed.' },
    { control: '5.12', title: 'Classification of Information', reason: 'Data classification not detailed in NCF.' },
    { control: '7.7', title: 'Clear Desk and Clear Screen', reason: 'Operational control not in NCF.' },
    { control: '8.6', title: 'Capacity Management', reason: 'IT capacity planning not addressed in NCF.' },
    { control: '8.9', title: 'Configuration Management', reason: 'Technical configuration control absent in NCF.' },
    { control: '8.17', title: 'Clock Synchronization', reason: 'Technical operational control not in NCF.' },
    { control: '8.31', title: 'Separation of Environments', reason: 'Development environment control not in NCF.' },
  ],
  structural_comparison: [
    { aspect: 'Structure', ghana: '6 Domains, 37 Controls', iso: '4 Themes, 93 Controls' },
    { aspect: 'Focus', ghana: 'National policy & governance-heavy', iso: 'Technical & operational controls' },
    { aspect: 'Scope', ghana: 'Ghana-specific regulatory context', iso: 'International best practice' },
    { aspect: 'Granularity', ghana: 'High-level strategic controls', iso: 'Detailed implementation guidance' },
    { aspect: 'Legal Context', ghana: 'Cybersecurity Act 2020 (Act 1038)', iso: 'Framework-agnostic' },
    { aspect: 'Update Cycle', ghana: 'Policy-driven updates', iso: 'Periodic ISO revisions' },
    { aspect: 'Certification', ghana: 'Regulatory compliance', iso: 'ISO 27001 certification support' },
    { aspect: 'Audience', ghana: 'Ghanaian organizations & government', iso: 'Global organizations' },
  ],
};

module.exports = { GAP_ANALYSIS };
