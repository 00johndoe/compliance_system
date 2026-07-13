#!/usr/bin/env python3
"""
Ghana NCF vs ISO/IEC 27002 Compliance Measurement System - Backend Server
"""

import http.server
import json
import os
import uuid
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# ─── In-memory storage ───
assessments_db = {}

# ─── Ghana NCF Controls ───
GHANA_NCF = {
    "name": "Ghana National Cybersecurity Framework",
    "version": "2024",
    "domains": [
        {
            "id": "GOV",
            "name": "Governance & Leadership",
            "controls": [
                {"id": "GOV-01", "title": "Cybersecurity Governance Structure", "description": "Establish a governance structure with clear roles, responsibilities, and accountability for cybersecurity.", "weight": 5},
                {"id": "GOV-02", "title": "National Cybersecurity Strategy Alignment", "description": "Align organizational strategy with Ghana's national cybersecurity policy objectives.", "weight": 4},
                {"id": "GOV-03", "title": "Regulatory Compliance Management", "description": "Ensure compliance with Ghana's Cybersecurity Act (Act 1038) and related regulations.", "weight": 5},
                {"id": "GOV-04", "title": "Cybersecurity Budget & Resource Allocation", "description": "Allocate adequate budget and resources for cybersecurity programs.", "weight": 4},
                {"id": "GOV-05", "title": "Board-Level Cybersecurity Oversight", "description": "Ensure board-level awareness and oversight of cybersecurity risks.", "weight": 4},
                {"id": "GOV-06", "title": "Stakeholder Engagement", "description": "Engage with national and international cybersecurity stakeholders.", "weight": 3}
            ]
        },
        {
            "id": "RISK",
            "name": "Risk Management",
            "controls": [
                {"id": "RISK-01", "title": "Risk Assessment Framework", "description": "Implement a structured risk assessment framework aligned with national standards.", "weight": 5},
                {"id": "RISK-02", "title": "Threat Intelligence Integration", "description": "Integrate threat intelligence from Ghana CERT and other sources.", "weight": 4},
                {"id": "RISK-03", "title": "Risk Treatment & Mitigation", "description": "Develop and implement risk treatment plans with defined acceptance criteria.", "weight": 5},
                {"id": "RISK-04", "title": "Third-Party Risk Management", "description": "Assess and manage cybersecurity risks from third-party vendors and suppliers.", "weight": 4},
                {"id": "RISK-05", "title": "Risk Monitoring & Review", "description": "Continuously monitor and review cybersecurity risks.", "weight": 4},
                {"id": "RISK-06", "title": "Critical Infrastructure Risk Assessment", "description": "Conduct specific risk assessments for critical national infrastructure.", "weight": 5}
            ]
        },
        {
            "id": "PROT",
            "name": "Protection & Defense",
            "controls": [
                {"id": "PROT-01", "title": "Access Control Management", "description": "Implement role-based access controls and identity management systems.", "weight": 5},
                {"id": "PROT-02", "title": "Data Protection & Privacy", "description": "Protect personal and sensitive data in compliance with Ghana's Data Protection Act.", "weight": 5},
                {"id": "PROT-03", "title": "Network Security Architecture", "description": "Design and maintain secure network architectures with defense-in-depth.", "weight": 5},
                {"id": "PROT-04", "title": "Encryption & Cryptographic Controls", "description": "Implement encryption for data at rest and in transit.", "weight": 4},
                {"id": "PROT-05", "title": "Endpoint Security", "description": "Deploy and manage endpoint protection solutions across all devices.", "weight": 4},
                {"id": "PROT-06", "title": "Application Security", "description": "Ensure secure development and deployment of applications.", "weight": 4},
                {"id": "PROT-07", "title": "Physical Security of IT Assets", "description": "Protect physical IT infrastructure from unauthorized access and environmental threats.", "weight": 3}
            ]
        },
        {
            "id": "DETECT",
            "name": "Detection & Monitoring",
            "controls": [
                {"id": "DETECT-01", "title": "Security Event Monitoring", "description": "Implement continuous security event monitoring and logging.", "weight": 5},
                {"id": "DETECT-02", "title": "Intrusion Detection Systems", "description": "Deploy and maintain intrusion detection and prevention systems.", "weight": 4},
                {"id": "DETECT-03", "title": "Security Audit & Assessment", "description": "Conduct regular security audits, vulnerability assessments, and penetration testing.", "weight": 5},
                {"id": "DETECT-04", "title": "Anomaly Detection", "description": "Implement behavioral analytics and anomaly detection capabilities.", "weight": 3},
                {"id": "DETECT-05", "title": "Log Management & Analysis", "description": "Centralize and analyze security logs for threat identification.", "weight": 4},
                {"id": "DETECT-06", "title": "Threat Hunting", "description": "Proactively search for threats that evade existing detection mechanisms.", "weight": 3}
            ]
        },
        {
            "id": "RESP",
            "name": "Incident Response & Recovery",
            "controls": [
                {"id": "RESP-01", "title": "Incident Response Plan", "description": "Develop and maintain a comprehensive incident response plan.", "weight": 5},
                {"id": "RESP-02", "title": "Incident Reporting to Cyber Security Authority", "description": "Report cybersecurity incidents to Ghana's Cyber Security Authority as required.", "weight": 5},
                {"id": "RESP-03", "title": "Digital Forensics Capability", "description": "Maintain digital forensics capabilities for incident investigation.", "weight": 4},
                {"id": "RESP-04", "title": "Business Continuity Planning", "description": "Develop and test business continuity and disaster recovery plans.", "weight": 5},
                {"id": "RESP-05", "title": "Incident Communication Protocol", "description": "Establish communication protocols for incident notification and escalation.", "weight": 4},
                {"id": "RESP-06", "title": "Post-Incident Review", "description": "Conduct post-incident reviews and implement lessons learned.", "weight": 4}
            ]
        },
        {
            "id": "CAP",
            "name": "Capacity Building & Awareness",
            "controls": [
                {"id": "CAP-01", "title": "Cybersecurity Awareness Program", "description": "Implement organization-wide cybersecurity awareness training.", "weight": 5},
                {"id": "CAP-02", "title": "Technical Skills Development", "description": "Develop and maintain technical cybersecurity skills within the organization.", "weight": 4},
                {"id": "CAP-03", "title": "Cybersecurity Culture", "description": "Foster a culture of cybersecurity responsibility across the organization.", "weight": 4},
                {"id": "CAP-04", "title": "Local Talent Pipeline", "description": "Support development of local cybersecurity talent and expertise.", "weight": 3},
                {"id": "CAP-05", "title": "Knowledge Sharing & Collaboration", "description": "Participate in cybersecurity knowledge sharing and collaboration initiatives.", "weight": 3},
                {"id": "CAP-06", "title": "Certification & Professional Development", "description": "Support cybersecurity certification and continuous professional development.", "weight": 3}
            ]
        }
    ]
}

# ─── ISO/IEC 27002:2022 Controls ───
ISO27002 = {
    "name": "ISO/IEC 27002:2022",
    "version": "2022",
    "themes": [
        {
            "id": "ORG",
            "name": "Organizational Controls",
            "controls": [
                {"id": "5.1", "title": "Policies for Information Security", "weight": 5},
                {"id": "5.2", "title": "Information Security Roles and Responsibilities", "weight": 5},
                {"id": "5.3", "title": "Segregation of Duties", "weight": 4},
                {"id": "5.4", "title": "Management Responsibilities", "weight": 4},
                {"id": "5.5", "title": "Contact with Authorities", "weight": 3},
                {"id": "5.6", "title": "Contact with Special Interest Groups", "weight": 3},
                {"id": "5.7", "title": "Threat Intelligence", "weight": 4},
                {"id": "5.8", "title": "Information Security in Project Management", "weight": 3},
                {"id": "5.9", "title": "Inventory of Information and Other Assets", "weight": 4},
                {"id": "5.10", "title": "Acceptable Use of Information and Other Assets", "weight": 4},
                {"id": "5.11", "title": "Return of Assets", "weight": 3},
                {"id": "5.12", "title": "Classification of Information", "weight": 4},
                {"id": "5.13", "title": "Labelling of Information", "weight": 3},
                {"id": "5.14", "title": "Information Transfer", "weight": 4},
                {"id": "5.15", "title": "Access Control", "weight": 5},
                {"id": "5.16", "title": "Identity Management", "weight": 5},
                {"id": "5.17", "title": "Authentication Information", "weight": 5},
                {"id": "5.18", "title": "Access Rights", "weight": 5},
                {"id": "5.19", "title": "Information Security in Supplier Relationships", "weight": 4},
                {"id": "5.20", "title": "Addressing Information Security within Supplier Agreements", "weight": 4},
                {"id": "5.21", "title": "Managing Information Security in the ICT Supply Chain", "weight": 4},
                {"id": "5.22", "title": "Monitoring, Review and Change Management of Supplier Services", "weight": 3},
                {"id": "5.23", "title": "Information Security for Use of Cloud Services", "weight": 4},
                {"id": "5.24", "title": "Information Security Incident Management Planning and Preparation", "weight": 5},
                {"id": "5.25", "title": "Assessment and Decision on Information Security Events", "weight": 4},
                {"id": "5.26", "title": "Response to Information Security Incidents", "weight": 5},
                {"id": "5.27", "title": "Learning from Information Security Incidents", "weight": 4},
                {"id": "5.28", "title": "Collection of Evidence", "weight": 4},
                {"id": "5.29", "title": "Information Security During Disruption", "weight": 5},
                {"id": "5.30", "title": "ICT Readiness for Business Continuity", "weight": 5},
                {"id": "5.31", "title": "Legal, Statutory, Regulatory and Contractual Requirements", "weight": 5},
                {"id": "5.32", "title": "Intellectual Property Rights", "weight": 3},
                {"id": "5.33", "title": "Protection of Records", "weight": 4},
                {"id": "5.34", "title": "Privacy and Protection of PII", "weight": 5},
                {"id": "5.35", "title": "Independent Review of Information Security", "weight": 4},
                {"id": "5.36", "title": "Compliance with Policies, Rules and Standards", "weight": 4},
                {"id": "5.37", "title": "Documented Operating Procedures", "weight": 4}
            ]
        },
        {
            "id": "PEOPLE",
            "name": "People Controls",
            "controls": [
                {"id": "6.1", "title": "Screening", "weight": 4},
                {"id": "6.2", "title": "Terms and Conditions of Employment", "weight": 4},
                {"id": "6.3", "title": "Information Security Awareness, Education and Training", "weight": 5},
                {"id": "6.4", "title": "Disciplinary Process", "weight": 3},
                {"id": "6.5", "title": "Responsibilities After Termination or Change of Employment", "weight": 3},
                {"id": "6.6", "title": "Confidentiality or Non-Disclosure Agreements", "weight": 4},
                {"id": "6.7", "title": "Remote Working", "weight": 4},
                {"id": "6.8", "title": "Information Security Event Reporting", "weight": 4}
            ]
        },
        {
            "id": "PHYSICAL",
            "name": "Physical Controls",
            "controls": [
                {"id": "7.1", "title": "Physical Security Perimeters", "weight": 4},
                {"id": "7.2", "title": "Physical Entry", "weight": 4},
                {"id": "7.3", "title": "Securing Offices, Rooms and Facilities", "weight": 3},
                {"id": "7.4", "title": "Physical Security Monitoring", "weight": 4},
                {"id": "7.5", "title": "Protecting Against Physical and Environmental Threats", "weight": 4},
                {"id": "7.6", "title": "Working in Secure Areas", "weight": 3},
                {"id": "7.7", "title": "Clear Desk and Clear Screen", "weight": 3},
                {"id": "7.8", "title": "Equipment Siting and Protection", "weight": 3},
                {"id": "7.9", "title": "Security of Assets Off-Premises", "weight": 3},
                {"id": "7.10", "title": "Storage Media", "weight": 4},
                {"id": "7.11", "title": "Supporting Utilities", "weight": 3},
                {"id": "7.12", "title": "Cabling Security", "weight": 3},
                {"id": "7.13", "title": "Equipment Maintenance", "weight": 3},
                {"id": "7.14", "title": "Secure Disposal or Re-Use of Equipment", "weight": 4}
            ]
        },
        {
            "id": "TECH",
            "name": "Technological Controls",
            "controls": [
                {"id": "8.1", "title": "User Endpoint Devices", "weight": 4},
                {"id": "8.2", "title": "Privileged Access Rights", "weight": 5},
                {"id": "8.3", "title": "Information Access Restriction", "weight": 4},
                {"id": "8.4", "title": "Access to Source Code", "weight": 3},
                {"id": "8.5", "title": "Secure Authentication", "weight": 5},
                {"id": "8.6", "title": "Capacity Management", "weight": 3},
                {"id": "8.7", "title": "Protection Against Malware", "weight": 5},
                {"id": "8.8", "title": "Management of Technical Vulnerabilities", "weight": 5},
                {"id": "8.9", "title": "Configuration Management", "weight": 4},
                {"id": "8.10", "title": "Information Deletion", "weight": 4},
                {"id": "8.11", "title": "Data Masking", "weight": 3},
                {"id": "8.12", "title": "Data Leakage Prevention", "weight": 4},
                {"id": "8.13", "title": "Information Backup", "weight": 5},
                {"id": "8.14", "title": "Redundancy of Information Processing Facilities", "weight": 4},
                {"id": "8.15", "title": "Logging", "weight": 5},
                {"id": "8.16", "title": "Monitoring Activities", "weight": 5},
                {"id": "8.17", "title": "Clock Synchronization", "weight": 3},
                {"id": "8.18", "title": "Use of Privileged Utility Programs", "weight": 4},
                {"id": "8.19", "title": "Installation of Software on Operational Systems", "weight": 4},
                {"id": "8.20", "title": "Networks Security", "weight": 5},
                {"id": "8.21", "title": "Security of Network Services", "weight": 4},
                {"id": "8.22", "title": "Segregation of Networks", "weight": 4},
                {"id": "8.23", "title": "Web Filtering", "weight": 3},
                {"id": "8.24", "title": "Use of Cryptography", "weight": 5},
                {"id": "8.25", "title": "Secure Development Life Cycle", "weight": 4},
                {"id": "8.26", "title": "Application Security Requirements", "weight": 4},
                {"id": "8.27", "title": "Secure System Architecture and Engineering Principles", "weight": 4},
                {"id": "8.28", "title": "Secure Coding", "weight": 4},
                {"id": "8.29", "title": "Security Testing in Development and Acceptance", "weight": 4},
                {"id": "8.30", "title": "Outsourced Development", "weight": 3},
                {"id": "8.31", "title": "Separation of Development, Test and Production Environments", "weight": 4},
                {"id": "8.32", "title": "Change Management", "weight": 4},
                {"id": "8.33", "title": "Test Information", "weight": 3},
                {"id": "8.34", "title": "Protection of Information Systems During Audit Testing", "weight": 3}
            ]
        }
    ]
}

# ─── Control Mapping (NCF → ISO 27002) ───
CONTROL_MAPPING = [
    {"ncf": "GOV-01", "iso": "5.1", "alignment": "Strong", "notes": "Both establish governance structures for security policy."},
    {"ncf": "GOV-01", "iso": "5.2", "alignment": "Strong", "notes": "Roles and responsibilities align with governance structure."},
    {"ncf": "GOV-02", "iso": "5.36", "alignment": "Moderate", "notes": "Strategy alignment partially maps to compliance with policies."},
    {"ncf": "GOV-03", "iso": "5.31", "alignment": "Strong", "notes": "Both address legal and regulatory compliance requirements."},
    {"ncf": "GOV-04", "iso": "5.4", "alignment": "Moderate", "notes": "Budget allocation relates to management responsibilities."},
    {"ncf": "GOV-05", "iso": "5.4", "alignment": "Strong", "notes": "Board oversight aligns with management responsibilities."},
    {"ncf": "GOV-06", "iso": "5.6", "alignment": "Strong", "notes": "Stakeholder engagement maps to special interest group contact."},
    {"ncf": "RISK-01", "iso": "5.7", "alignment": "Moderate", "notes": "Risk framework partially supported by threat intelligence."},
    {"ncf": "RISK-02", "iso": "5.7", "alignment": "Strong", "notes": "Direct mapping of threat intelligence integration."},
    {"ncf": "RISK-03", "iso": "8.8", "alignment": "Moderate", "notes": "Risk treatment relates to vulnerability management."},
    {"ncf": "RISK-04", "iso": "5.19", "alignment": "Strong", "notes": "Both address supplier/third-party security management."},
    {"ncf": "RISK-04", "iso": "5.21", "alignment": "Strong", "notes": "ICT supply chain risk directly maps."},
    {"ncf": "RISK-05", "iso": "5.22", "alignment": "Moderate", "notes": "Risk monitoring relates to supplier service monitoring."},
    {"ncf": "RISK-06", "iso": "5.29", "alignment": "Moderate", "notes": "Critical infrastructure risk maps to disruption security."},
    {"ncf": "PROT-01", "iso": "5.15", "alignment": "Strong", "notes": "Direct mapping of access control requirements."},
    {"ncf": "PROT-01", "iso": "5.16", "alignment": "Strong", "notes": "Identity management is a core component."},
    {"ncf": "PROT-01", "iso": "8.2", "alignment": "Strong", "notes": "Privileged access control directly maps."},
    {"ncf": "PROT-02", "iso": "5.34", "alignment": "Strong", "notes": "Both address privacy and PII protection."},
    {"ncf": "PROT-02", "iso": "8.11", "alignment": "Moderate", "notes": "Data masking supports data protection goals."},
    {"ncf": "PROT-03", "iso": "8.20", "alignment": "Strong", "notes": "Network security directly maps."},
    {"ncf": "PROT-03", "iso": "8.22", "alignment": "Strong", "notes": "Network segregation supports security architecture."},
    {"ncf": "PROT-04", "iso": "8.24", "alignment": "Strong", "notes": "Direct mapping of cryptographic controls."},
    {"ncf": "PROT-05", "iso": "8.1", "alignment": "Strong", "notes": "Endpoint devices map to endpoint security."},
    {"ncf": "PROT-05", "iso": "8.7", "alignment": "Strong", "notes": "Malware protection supports endpoint security."},
    {"ncf": "PROT-06", "iso": "8.25", "alignment": "Strong", "notes": "Secure SDLC maps to application security."},
    {"ncf": "PROT-06", "iso": "8.26", "alignment": "Strong", "notes": "Application security requirements directly map."},
    {"ncf": "PROT-07", "iso": "7.1", "alignment": "Strong", "notes": "Physical security perimeters directly map."},
    {"ncf": "PROT-07", "iso": "7.2", "alignment": "Strong", "notes": "Physical entry controls map."},
    {"ncf": "DETECT-01", "iso": "8.16", "alignment": "Strong", "notes": "Monitoring activities directly map."},
    {"ncf": "DETECT-02", "iso": "8.7", "alignment": "Moderate", "notes": "Malware protection partially supports IDS."},
    {"ncf": "DETECT-03", "iso": "5.35", "alignment": "Strong", "notes": "Independent review maps to security audits."},
    {"ncf": "DETECT-04", "iso": "8.16", "alignment": "Moderate", "notes": "Monitoring supports anomaly detection."},
    {"ncf": "DETECT-05", "iso": "8.15", "alignment": "Strong", "notes": "Logging directly maps to log management."},
    {"ncf": "DETECT-06", "iso": "5.7", "alignment": "Moderate", "notes": "Threat intelligence supports threat hunting."},
    {"ncf": "RESP-01", "iso": "5.24", "alignment": "Strong", "notes": "Incident management planning directly maps."},
    {"ncf": "RESP-01", "iso": "5.26", "alignment": "Strong", "notes": "Incident response directly maps."},
    {"ncf": "RESP-02", "iso": "6.8", "alignment": "Moderate", "notes": "Event reporting partially maps to authority reporting."},
    {"ncf": "RESP-03", "iso": "5.28", "alignment": "Strong", "notes": "Evidence collection supports digital forensics."},
    {"ncf": "RESP-04", "iso": "5.30", "alignment": "Strong", "notes": "ICT readiness for BC directly maps."},
    {"ncf": "RESP-05", "iso": "5.25", "alignment": "Moderate", "notes": "Event assessment partially maps to communication."},
    {"ncf": "RESP-06", "iso": "5.27", "alignment": "Strong", "notes": "Learning from incidents directly maps."},
    {"ncf": "CAP-01", "iso": "6.3", "alignment": "Strong", "notes": "Awareness and training directly maps."},
    {"ncf": "CAP-02", "iso": "6.3", "alignment": "Moderate", "notes": "Education component supports technical skills."},
    {"ncf": "CAP-03", "iso": "5.4", "alignment": "Moderate", "notes": "Management responsibilities support culture."},
    {"ncf": "CAP-04", "iso": "6.2", "alignment": "Partial", "notes": "Employment terms loosely relate to talent pipeline."},
    {"ncf": "CAP-05", "iso": "5.6", "alignment": "Moderate", "notes": "Special interest groups support collaboration."},
    {"ncf": "CAP-06", "iso": "6.3", "alignment": "Moderate", "notes": "Training supports professional development."},
]

# ─── Gap Analysis Data ───
GAP_ANALYSIS = {
    "ghana_unique": [
        {"control": "GOV-02", "title": "National Cybersecurity Strategy Alignment", "reason": "Specific to Ghana's national policy; no direct ISO equivalent."},
        {"control": "RISK-02", "title": "Threat Intelligence from Ghana CERT", "reason": "Ghana-specific threat intelligence source."},
        {"control": "RISK-06", "title": "Critical National Infrastructure Risk", "reason": "National infrastructure focus beyond ISO scope."},
        {"control": "RESP-02", "title": "Reporting to Cyber Security Authority", "reason": "Ghana-specific regulatory reporting requirement."},
        {"control": "CAP-04", "title": "Local Talent Pipeline", "reason": "National capacity building not in ISO scope."},
    ],
    "iso_unique": [
        {"control": "5.3", "title": "Segregation of Duties", "reason": "Detailed control not explicitly in Ghana NCF."},
        {"control": "5.9", "title": "Inventory of Information and Other Assets", "reason": "Asset inventory not explicitly addressed."},
        {"control": "5.12", "title": "Classification of Information", "reason": "Data classification not detailed in NCF."},
        {"control": "7.7", "title": "Clear Desk and Clear Screen", "reason": "Operational control not in NCF."},
        {"control": "8.6", "title": "Capacity Management", "reason": "IT capacity planning not addressed in NCF."},
        {"control": "8.9", "title": "Configuration Management", "reason": "Technical configuration control absent in NCF."},
        {"control": "8.17", "title": "Clock Synchronization", "reason": "Technical operational control not in NCF."},
        {"control": "8.31", "title": "Separation of Environments", "reason": "Development environment control not in NCF."},
    ],
    "structural_comparison": [
        {"aspect": "Structure", "ghana": "6 Domains, 37 Controls", "iso": "4 Themes, 93 Controls"},
        {"aspect": "Focus", "ghana": "National policy & governance-heavy", "iso": "Technical & operational controls"},
        {"aspect": "Scope", "ghana": "Ghana-specific regulatory context", "iso": "International best practice"},
        {"aspect": "Granularity", "ghana": "High-level strategic controls", "iso": "Detailed implementation guidance"},
        {"aspect": "Legal Context", "ghana": "Cybersecurity Act 2020 (Act 1038)", "iso": "Framework-agnostic"},
        {"aspect": "Update Cycle", "ghana": "Policy-driven updates", "iso": "Periodic ISO revisions"},
        {"aspect": "Certification", "ghana": "Regulatory compliance", "iso": "ISO 27001 certification support"},
        {"aspect": "Audience", "ghana": "Ghanaian organizations & government", "iso": "Global organizations"},
    ]
}


def calculate_scores(responses, framework_type):
    """Calculate compliance scores for a framework assessment."""
    if framework_type == "ghana":
        framework = GHANA_NCF
        groups = framework["domains"]
    else:
        framework = ISO27002
        groups = framework["themes"]

    domain_scores = []
    total_weighted_score = 0
    total_weight = 0

    for group in groups:
        group_score = 0
        group_weight = 0
        control_results = []
        for control in group["controls"]:
            cid = control["id"]
            maturity = responses.get(cid, 0)
            weight = control["weight"]
            score = (maturity / 5) * 100
            weighted = score * weight
            group_score += weighted
            group_weight += weight
            total_weighted_score += weighted
            total_weight += weight
            control_results.append({
                "id": cid,
                "title": control["title"],
                "maturity": maturity,
                "score": round(score, 1),
                "weight": weight,
            })

        avg = round(group_score / group_weight, 1) if group_weight > 0 else 0
        domain_scores.append({
            "id": group["id"],
            "name": group["name"],
            "score": avg,
            "controls": control_results,
        })

    overall = round(total_weighted_score / total_weight, 1) if total_weight > 0 else 0
    return {"overall": overall, "domains": domain_scores}


def get_maturity_label(score):
    if score >= 90: return "Optimized"
    if score >= 70: return "Managed"
    if score >= 50: return "Defined"
    if score >= 30: return "Developing"
    if score >= 10: return "Initial"
    return "Non-Existent"


def generate_recommendations(ghana_scores, iso_scores):
    """Generate prioritized recommendations."""
    recs = []
    all_controls = []
    for d in ghana_scores["domains"]:
        for c in d["controls"]:
            all_controls.append({**c, "framework": "Ghana NCF", "domain": d["name"]})
    for d in iso_scores["domains"]:
        for c in d["controls"]:
            all_controls.append({**c, "framework": "ISO 27002", "domain": d["name"]})

    for ctrl in all_controls:
        if ctrl["score"] < 40 and ctrl["weight"] >= 4:
            recs.append({
                "priority": "Critical",
                "control": f"{ctrl['framework']} - {ctrl['id']}",
                "title": ctrl["title"],
                "current_score": ctrl["score"],
                "target_score": 80,
                "recommendation": f"Urgently implement {ctrl['title']}. Current maturity is critically low for a high-weight control.",
            })
        elif ctrl["score"] < 60 and ctrl["weight"] >= 4:
            recs.append({
                "priority": "High",
                "control": f"{ctrl['framework']} - {ctrl['id']}",
                "title": ctrl["title"],
                "current_score": ctrl["score"],
                "target_score": 80,
                "recommendation": f"Prioritize improvement of {ctrl['title']} to meet compliance targets.",
            })
        elif ctrl["score"] < 60:
            recs.append({
                "priority": "Medium",
                "control": f"{ctrl['framework']} - {ctrl['id']}",
                "title": ctrl["title"],
                "current_score": ctrl["score"],
                "target_score": 70,
                "recommendation": f"Plan improvement of {ctrl['title']} in the next review cycle.",
            })
        elif ctrl["score"] < 80:
            recs.append({
                "priority": "Low",
                "control": f"{ctrl['framework']} - {ctrl['id']}",
                "title": ctrl["title"],
                "current_score": ctrl["score"],
                "target_score": 90,
                "recommendation": f"Fine-tune {ctrl['title']} to achieve optimized maturity level.",
            })

    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    recs.sort(key=lambda x: (priority_order.get(x["priority"], 4), -x["current_score"]))
    return recs


class ComplianceHandler(http.server.SimpleHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/frameworks/ghana":
            self.send_json(GHANA_NCF)
        elif path == "/api/frameworks/iso27002":
            self.send_json(ISO27002)
        elif path == "/api/mapping":
            self.send_json(CONTROL_MAPPING)
        elif path == "/api/gaps":
            self.send_json(GAP_ANALYSIS)
        elif path == "/api/assessments":
            summaries = []
            for aid, a in assessments_db.items():
                summaries.append({
                    "id": aid,
                    "organization": a["organization"],
                    "date": a["date"],
                    "ghana_score": a["ghana_scores"]["overall"],
                    "iso_score": a["iso_scores"]["overall"],
                })
            self.send_json(summaries)
        elif path.startswith("/api/assessments/"):
            aid = path.split("/")[-1]
            if aid in assessments_db:
                self.send_json(assessments_db[aid])
            else:
                self.send_json({"error": "Assessment not found"}, 404)
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length > 0 else {}

        if path == "/api/assess":
            org = body.get("organization", {})
            ghana_responses = body.get("ghana_responses", {})
            iso_responses = body.get("iso_responses", {})

            ghana_scores = calculate_scores(ghana_responses, "ghana")
            iso_scores = calculate_scores(iso_responses, "iso")
            recommendations = generate_recommendations(ghana_scores, iso_scores)

            assessment_id = str(uuid.uuid4())[:8]
            result = {
                "id": assessment_id,
                "organization": org,
                "date": datetime.now().isoformat(),
                "ghana_scores": ghana_scores,
                "iso_scores": iso_scores,
                "recommendations": recommendations,
                "alignment_score": round((ghana_scores["overall"] + iso_scores["overall"]) / 2, 1),
                "ghana_maturity": get_maturity_label(ghana_scores["overall"]),
                "iso_maturity": get_maturity_label(iso_scores["overall"]),
            }
            assessments_db[assessment_id] = result
            self.send_json(result)

        elif path == "/api/report":
            aid = body.get("assessment_id", "")
            if aid in assessments_db:
                self.send_json(assessments_db[aid])
            else:
                self.send_json({"error": "Assessment not found"}, 404)
        else:
            self.send_json({"error": "Not found"}, 404)


if __name__ == "__main__":
    PORT = 8000
    print(f"\n{'='*60}")
    print(f"  Ghana NCF vs ISO/IEC 27002 Compliance System")
    print(f"  Server running at http://localhost:{PORT}")
    print(f"{'='*60}\n")
    server = http.server.HTTPServer(("", PORT), ComplianceHandler)
    server.serve_forever()
