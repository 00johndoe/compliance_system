'use strict';

/**
 * Canonical framework reference data.
 *
 * The Ghana side is built from data/ghana-requirements.json; the ISO/IEC 27002 side
 * was ported from the retired server.py. These structures are seeded into
 * MongoDB (see src/seed.js) and also serve as the fallback source of truth when
 * the DB is empty.
 */

// ─── Ghana requirements ───
// Built from data/ghana-requirements.json (the single source of truth shared
// with the browser via gh-requirements.js). Not an official CSA control
// catalogue: each item is a paraphrase of a cited legal or directive requirement.
const REQUIREMENTS = require('../../../data/ghana-requirements.json');

// Every requirement is a legal obligation, so all carry the same criticality
// weight. The weight only influences recommendation priority, never the score.
const REQUIREMENT_WEIGHT = 4;

const GHANA_REQUIREMENTS = {
  key: 'ghana',
  name: REQUIREMENTS.name,
  version: REQUIREMENTS.version,
  groupLabel: 'domains',
  domains: REQUIREMENTS.groups
    .map((g) => ({
      id: g.id,
      name: g.name,
      controls: REQUIREMENTS.requirements
        .filter((r) => r.group === g.id)
        .map((r) => ({
          id: r.id,
          title: r.title,
          description: r.requirement,
          weight: REQUIREMENT_WEIGHT,
          tier: r.tier,
          source: r.source,
        })),
    }))
    .filter((g) => g.controls.length > 0),
};

// ─── ISO/IEC 27002:2022 ───
const ISO27002 = {
  key: 'iso27002',
  name: 'ISO/IEC 27002:2022',
  version: '2022',
  groupLabel: 'themes',
  themes: [
    {
      id: 'ORG',
      name: 'Organizational Controls',
      controls: [
        { id: '5.1', title: 'Policies for Information Security', weight: 5 },
        { id: '5.2', title: 'Information Security Roles and Responsibilities', weight: 5 },
        { id: '5.3', title: 'Segregation of Duties', weight: 4 },
        { id: '5.4', title: 'Management Responsibilities', weight: 4 },
        { id: '5.5', title: 'Contact with Authorities', weight: 3 },
        { id: '5.6', title: 'Contact with Special Interest Groups', weight: 3 },
        { id: '5.7', title: 'Threat Intelligence', weight: 4 },
        { id: '5.8', title: 'Information Security in Project Management', weight: 3 },
        { id: '5.9', title: 'Inventory of Information and Other Assets', weight: 4 },
        { id: '5.10', title: 'Acceptable Use of Information and Other Assets', weight: 4 },
        { id: '5.11', title: 'Return of Assets', weight: 3 },
        { id: '5.12', title: 'Classification of Information', weight: 4 },
        { id: '5.13', title: 'Labelling of Information', weight: 3 },
        { id: '5.14', title: 'Information Transfer', weight: 4 },
        { id: '5.15', title: 'Access Control', weight: 5 },
        { id: '5.16', title: 'Identity Management', weight: 5 },
        { id: '5.17', title: 'Authentication Information', weight: 5 },
        { id: '5.18', title: 'Access Rights', weight: 5 },
        { id: '5.19', title: 'Information Security in Supplier Relationships', weight: 4 },
        { id: '5.20', title: 'Addressing Information Security within Supplier Agreements', weight: 4 },
        { id: '5.21', title: 'Managing Information Security in the ICT Supply Chain', weight: 4 },
        { id: '5.22', title: 'Monitoring, Review and Change Management of Supplier Services', weight: 3 },
        { id: '5.23', title: 'Information Security for Use of Cloud Services', weight: 4 },
        { id: '5.24', title: 'Information Security Incident Management Planning and Preparation', weight: 5 },
        { id: '5.25', title: 'Assessment and Decision on Information Security Events', weight: 4 },
        { id: '5.26', title: 'Response to Information Security Incidents', weight: 5 },
        { id: '5.27', title: 'Learning from Information Security Incidents', weight: 4 },
        { id: '5.28', title: 'Collection of Evidence', weight: 4 },
        { id: '5.29', title: 'Information Security During Disruption', weight: 5 },
        { id: '5.30', title: 'ICT Readiness for Business Continuity', weight: 5 },
        { id: '5.31', title: 'Legal, Statutory, Regulatory and Contractual Requirements', weight: 5 },
        { id: '5.32', title: 'Intellectual Property Rights', weight: 3 },
        { id: '5.33', title: 'Protection of Records', weight: 4 },
        { id: '5.34', title: 'Privacy and Protection of PII', weight: 5 },
        { id: '5.35', title: 'Independent Review of Information Security', weight: 4 },
        { id: '5.36', title: 'Compliance with Policies, Rules and Standards', weight: 4 },
        { id: '5.37', title: 'Documented Operating Procedures', weight: 4 },
      ],
    },
    {
      id: 'PEOPLE',
      name: 'People Controls',
      controls: [
        { id: '6.1', title: 'Screening', weight: 4 },
        { id: '6.2', title: 'Terms and Conditions of Employment', weight: 4 },
        { id: '6.3', title: 'Information Security Awareness, Education and Training', weight: 5 },
        { id: '6.4', title: 'Disciplinary Process', weight: 3 },
        { id: '6.5', title: 'Responsibilities After Termination or Change of Employment', weight: 3 },
        { id: '6.6', title: 'Confidentiality or Non-Disclosure Agreements', weight: 4 },
        { id: '6.7', title: 'Remote Working', weight: 4 },
        { id: '6.8', title: 'Information Security Event Reporting', weight: 4 },
      ],
    },
    {
      id: 'PHYSICAL',
      name: 'Physical Controls',
      controls: [
        { id: '7.1', title: 'Physical Security Perimeters', weight: 4 },
        { id: '7.2', title: 'Physical Entry', weight: 4 },
        { id: '7.3', title: 'Securing Offices, Rooms and Facilities', weight: 3 },
        { id: '7.4', title: 'Physical Security Monitoring', weight: 4 },
        { id: '7.5', title: 'Protecting Against Physical and Environmental Threats', weight: 4 },
        { id: '7.6', title: 'Working in Secure Areas', weight: 3 },
        { id: '7.7', title: 'Clear Desk and Clear Screen', weight: 3 },
        { id: '7.8', title: 'Equipment Siting and Protection', weight: 3 },
        { id: '7.9', title: 'Security of Assets Off-Premises', weight: 3 },
        { id: '7.10', title: 'Storage Media', weight: 4 },
        { id: '7.11', title: 'Supporting Utilities', weight: 3 },
        { id: '7.12', title: 'Cabling Security', weight: 3 },
        { id: '7.13', title: 'Equipment Maintenance', weight: 3 },
        { id: '7.14', title: 'Secure Disposal or Re-Use of Equipment', weight: 4 },
      ],
    },
    {
      id: 'TECH',
      name: 'Technological Controls',
      controls: [
        { id: '8.1', title: 'User Endpoint Devices', weight: 4 },
        { id: '8.2', title: 'Privileged Access Rights', weight: 5 },
        { id: '8.3', title: 'Information Access Restriction', weight: 4 },
        { id: '8.4', title: 'Access to Source Code', weight: 3 },
        { id: '8.5', title: 'Secure Authentication', weight: 5 },
        { id: '8.6', title: 'Capacity Management', weight: 3 },
        { id: '8.7', title: 'Protection Against Malware', weight: 5 },
        { id: '8.8', title: 'Management of Technical Vulnerabilities', weight: 5 },
        { id: '8.9', title: 'Configuration Management', weight: 4 },
        { id: '8.10', title: 'Information Deletion', weight: 4 },
        { id: '8.11', title: 'Data Masking', weight: 3 },
        { id: '8.12', title: 'Data Leakage Prevention', weight: 4 },
        { id: '8.13', title: 'Information Backup', weight: 5 },
        { id: '8.14', title: 'Redundancy of Information Processing Facilities', weight: 4 },
        { id: '8.15', title: 'Logging', weight: 5 },
        { id: '8.16', title: 'Monitoring Activities', weight: 5 },
        { id: '8.17', title: 'Clock Synchronization', weight: 3 },
        { id: '8.18', title: 'Use of Privileged Utility Programs', weight: 4 },
        { id: '8.19', title: 'Installation of Software on Operational Systems', weight: 4 },
        { id: '8.20', title: 'Networks Security', weight: 5 },
        { id: '8.21', title: 'Security of Network Services', weight: 4 },
        { id: '8.22', title: 'Segregation of Networks', weight: 4 },
        { id: '8.23', title: 'Web Filtering', weight: 3 },
        { id: '8.24', title: 'Use of Cryptography', weight: 5 },
        { id: '8.25', title: 'Secure Development Life Cycle', weight: 4 },
        { id: '8.26', title: 'Application Security Requirements', weight: 4 },
        { id: '8.27', title: 'Secure System Architecture and Engineering Principles', weight: 4 },
        { id: '8.28', title: 'Secure Coding', weight: 4 },
        { id: '8.29', title: 'Security Testing in Development and Acceptance', weight: 4 },
        { id: '8.30', title: 'Outsourced Development', weight: 3 },
        { id: '8.31', title: 'Separation of Development, Test and Production Environments', weight: 4 },
        { id: '8.32', title: 'Change Management', weight: 4 },
        { id: '8.33', title: 'Test Information', weight: 3 },
        { id: '8.34', title: 'Protection of Information Systems During Audit Testing', weight: 3 },
      ],
    },
  ],
};

/** Returns the group array (domains/themes) for a framework document. */
function getGroups(framework) {
  return framework.domains || framework.themes || [];
}

/** Flattens a framework into a list of controls tagged with their group. */
function flattenControls(framework) {
  const groups = getGroups(framework);
  const out = [];
  for (const group of groups) {
    for (const control of group.controls) {
      out.push({ ...control, groupId: group.id, groupName: group.name });
    }
  }
  return out;
}

module.exports = { GHANA_REQUIREMENTS, ISO27002, REQUIREMENTS, getGroups, flattenControls };
