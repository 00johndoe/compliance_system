'use strict';

/**
 * Canonical framework reference data.
 *
 * Ported faithfully from the original server.py reference model so the Node
 * backend is a drop-in, superset replacement. These structures are seeded into
 * MongoDB (see src/seed.js) and also serve as the fallback source of truth when
 * the DB is empty.
 */

// ─── Ghana National Cybersecurity Framework ───
const GHANA_NCF = {
  key: 'ghana',
  name: 'Ghana National Cybersecurity Framework',
  version: '2024',
  groupLabel: 'domains',
  domains: [
    {
      id: 'GOV',
      name: 'Governance & Leadership',
      controls: [
        { id: 'GOV-01', title: 'Cybersecurity Governance Structure', description: 'Establish a governance structure with clear roles, responsibilities, and accountability for cybersecurity.', weight: 5 },
        { id: 'GOV-02', title: 'National Cybersecurity Strategy Alignment', description: "Align organizational strategy with Ghana's national cybersecurity policy objectives.", weight: 4 },
        { id: 'GOV-03', title: 'Regulatory Compliance Management', description: "Ensure compliance with Ghana's Cybersecurity Act (Act 1038) and related regulations.", weight: 5 },
        { id: 'GOV-04', title: 'Cybersecurity Budget & Resource Allocation', description: 'Allocate adequate budget and resources for cybersecurity programs.', weight: 4 },
        { id: 'GOV-05', title: 'Board-Level Cybersecurity Oversight', description: 'Ensure board-level awareness and oversight of cybersecurity risks.', weight: 4 },
        { id: 'GOV-06', title: 'Stakeholder Engagement', description: 'Engage with national and international cybersecurity stakeholders.', weight: 3 },
      ],
    },
    {
      id: 'RISK',
      name: 'Risk Management',
      controls: [
        { id: 'RISK-01', title: 'Risk Assessment Framework', description: 'Implement a structured risk assessment framework aligned with national standards.', weight: 5 },
        { id: 'RISK-02', title: 'Threat Intelligence Integration', description: 'Integrate threat intelligence from Ghana CERT and other sources.', weight: 4 },
        { id: 'RISK-03', title: 'Risk Treatment & Mitigation', description: 'Develop and implement risk treatment plans with defined acceptance criteria.', weight: 5 },
        { id: 'RISK-04', title: 'Third-Party Risk Management', description: 'Assess and manage cybersecurity risks from third-party vendors and suppliers.', weight: 4 },
        { id: 'RISK-05', title: 'Risk Monitoring & Review', description: 'Continuously monitor and review cybersecurity risks.', weight: 4 },
        { id: 'RISK-06', title: 'Critical Infrastructure Risk Assessment', description: 'Conduct specific risk assessments for critical national infrastructure.', weight: 5 },
      ],
    },
    {
      id: 'PROT',
      name: 'Protection & Defense',
      controls: [
        { id: 'PROT-01', title: 'Access Control Management', description: 'Implement role-based access controls and identity management systems.', weight: 5 },
        { id: 'PROT-02', title: 'Data Protection & Privacy', description: "Protect personal and sensitive data in compliance with Ghana's Data Protection Act.", weight: 5 },
        { id: 'PROT-03', title: 'Network Security Architecture', description: 'Design and maintain secure network architectures with defense-in-depth.', weight: 5 },
        { id: 'PROT-04', title: 'Encryption & Cryptographic Controls', description: 'Implement encryption for data at rest and in transit.', weight: 4 },
        { id: 'PROT-05', title: 'Endpoint Security', description: 'Deploy and manage endpoint protection solutions across all devices.', weight: 4 },
        { id: 'PROT-06', title: 'Application Security', description: 'Ensure secure development and deployment of applications.', weight: 4 },
        { id: 'PROT-07', title: 'Physical Security of IT Assets', description: 'Protect physical IT infrastructure from unauthorized access and environmental threats.', weight: 3 },
      ],
    },
    {
      id: 'DETECT',
      name: 'Detection & Monitoring',
      controls: [
        { id: 'DETECT-01', title: 'Security Event Monitoring', description: 'Implement continuous security event monitoring and logging.', weight: 5 },
        { id: 'DETECT-02', title: 'Intrusion Detection Systems', description: 'Deploy and maintain intrusion detection and prevention systems.', weight: 4 },
        { id: 'DETECT-03', title: 'Security Audit & Assessment', description: 'Conduct regular security audits, vulnerability assessments, and penetration testing.', weight: 5 },
        { id: 'DETECT-04', title: 'Anomaly Detection', description: 'Implement behavioral analytics and anomaly detection capabilities.', weight: 3 },
        { id: 'DETECT-05', title: 'Log Management & Analysis', description: 'Centralize and analyze security logs for threat identification.', weight: 4 },
        { id: 'DETECT-06', title: 'Threat Hunting', description: 'Proactively search for threats that evade existing detection mechanisms.', weight: 3 },
      ],
    },
    {
      id: 'RESP',
      name: 'Incident Response & Recovery',
      controls: [
        { id: 'RESP-01', title: 'Incident Response Plan', description: 'Develop and maintain a comprehensive incident response plan.', weight: 5 },
        { id: 'RESP-02', title: 'Incident Reporting to Cyber Security Authority', description: "Report cybersecurity incidents to Ghana's Cyber Security Authority as required.", weight: 5 },
        { id: 'RESP-03', title: 'Digital Forensics Capability', description: 'Maintain digital forensics capabilities for incident investigation.', weight: 4 },
        { id: 'RESP-04', title: 'Business Continuity Planning', description: 'Develop and test business continuity and disaster recovery plans.', weight: 5 },
        { id: 'RESP-05', title: 'Incident Communication Protocol', description: 'Establish communication protocols for incident notification and escalation.', weight: 4 },
        { id: 'RESP-06', title: 'Post-Incident Review', description: 'Conduct post-incident reviews and implement lessons learned.', weight: 4 },
      ],
    },
    {
      id: 'CAP',
      name: 'Capacity Building & Awareness',
      controls: [
        { id: 'CAP-01', title: 'Cybersecurity Awareness Program', description: 'Implement organization-wide cybersecurity awareness training.', weight: 5 },
        { id: 'CAP-02', title: 'Technical Skills Development', description: 'Develop and maintain technical cybersecurity skills within the organization.', weight: 4 },
        { id: 'CAP-03', title: 'Cybersecurity Culture', description: 'Foster a culture of cybersecurity responsibility across the organization.', weight: 4 },
        { id: 'CAP-04', title: 'Local Talent Pipeline', description: 'Support development of local cybersecurity talent and expertise.', weight: 3 },
        { id: 'CAP-05', title: 'Knowledge Sharing & Collaboration', description: 'Participate in cybersecurity knowledge sharing and collaboration initiatives.', weight: 3 },
        { id: 'CAP-06', title: 'Certification & Professional Development', description: 'Support cybersecurity certification and continuous professional development.', weight: 3 },
      ],
    },
  ],
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

module.exports = { GHANA_NCF, ISO27002, getGroups, flattenControls };
