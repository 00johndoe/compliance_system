"""
Ghana National Cybersecurity Framework vs ISO/IEC 27002
Automated Compliance Measurement System - Backend API
"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import os
from datetime import datetime
import hashlib
import uuid

# ============================================================
# DATA: Control Mappings between Ghana NCF and ISO/IEC 27002
# ============================================================

GHANA_NCF_DOMAINS = {
    "GOV": {
        "id": "GOV",
        "name": "Governance & Leadership",
        "description": "Establishes cybersecurity governance structures, roles, responsibilities, and oversight mechanisms.",
        "controls": {
            "GOV-01": {"title": "Cybersecurity Policy", "description": "Establish and maintain a formal cybersecurity policy approved by senior management.", "weight": 5},
            "GOV-02": {"title": "Governance Structure", "description": "Define cybersecurity governance structure with clear roles and responsibilities.", "weight": 5},
            "GOV-03": {"title": "Risk Management Framework", "description": "Implement a cybersecurity risk management framework aligned with organizational objectives.", "weight": 5},
            "GOV-04": {"title": "Regulatory Compliance", "description": "Ensure compliance with Ghana's Data Protection Act and Cybersecurity Act.", "weight": 4},
            "GOV-05": {"title": "Resource Allocation", "description": "Allocate adequate resources for cybersecurity programs and initiatives.", "weight": 4},
            "GOV-06": {"title": "Board Oversight", "description": "Ensure board-level oversight and reporting on cybersecurity matters.", "weight": 4},
            "GOV-07": {"title": "Performance Metrics", "description": "Define and track cybersecurity performance metrics and KPIs.", "weight": 3},
        }
    },
    "IDN": {
        "id": "IDN",
        "name": "Identify & Assess",
        "description": "Identifies critical assets, threats, vulnerabilities, and conducts risk assessments.",
        "controls": {
            "IDN-01": {"title": "Asset Inventory", "description": "Maintain a comprehensive inventory of all information assets.", "weight": 5},
            "IDN-02": {"title": "Risk Assessment", "description": "Conduct regular cybersecurity risk assessments.", "weight": 5},
            "IDN-03": {"title": "Threat Intelligence", "description": "Establish threat intelligence capabilities and information sharing.", "weight": 4},
            "IDN-04": {"title": "Vulnerability Management", "description": "Implement vulnerability identification and management processes.", "weight": 5},
            "IDN-05": {"title": "Business Impact Analysis", "description": "Conduct business impact analysis for critical systems and services.", "weight": 4},
            "IDN-06": {"title": "Supply Chain Risk", "description": "Assess and manage cybersecurity risks in the supply chain.", "weight": 3},
        }
    },
    "PRO": {
        "id": "PRO",
        "name": "Protect & Defend",
        "description": "Implements safeguards to protect critical infrastructure and information assets.",
        "controls": {
            "PRO-01": {"title": "Access Control", "description": "Implement role-based access control and least privilege principles.", "weight": 5},
            "PRO-02": {"title": "Data Protection", "description": "Implement data classification, encryption, and protection mechanisms.", "weight": 5},
            "PRO-03": {"title": "Network Security", "description": "Deploy network security controls including firewalls, IDS/IPS, and segmentation.", "weight": 5},
            "PRO-04": {"title": "Endpoint Protection", "description": "Implement endpoint security solutions and management.", "weight": 4},
            "PRO-05": {"title": "Security Awareness Training", "description": "Conduct regular cybersecurity awareness and training programs.", "weight": 4},
            "PRO-06": {"title": "Cryptographic Controls", "description": "Implement appropriate cryptographic controls and key management.", "weight": 4},
            "PRO-07": {"title": "Physical Security", "description": "Implement physical security controls for IT infrastructure.", "weight": 3},
            "PRO-08": {"title": "Secure Configuration", "description": "Maintain secure configurations for all systems and devices.", "weight": 4},
            "PRO-09": {"title": "Application Security", "description": "Implement secure software development lifecycle practices.", "weight": 4},
        }
    },
    "DET": {
        "id": "DET",
        "name": "Detect & Monitor",
        "description": "Establishes capabilities to detect cybersecurity events and continuous monitoring.",
        "controls": {
            "DET-01": {"title": "Security Monitoring", "description": "Implement continuous security monitoring and SIEM capabilities.", "weight": 5},
            "DET-02": {"title": "Log Management", "description": "Implement centralized log collection, analysis, and retention.", "weight": 5},
            "DET-03": {"title": "Anomaly Detection", "description": "Deploy anomaly and behavioral detection mechanisms.", "weight": 4},
            "DET-04": {"title": "Threat Detection", "description": "Implement advanced threat detection capabilities.", "weight": 4},
            "DET-05": {"title": "Security Auditing", "description": "Conduct regular security audits and assessments.", "weight": 4},
        }
    },
    "RES": {
        "id": "RES",
        "name": "Respond & Recover",
        "description": "Establishes incident response and recovery capabilities.",
        "controls": {
            "RES-01": {"title": "Incident Response Plan", "description": "Develop and maintain a cybersecurity incident response plan.", "weight": 5},
            "RES-02": {"title": "Incident Response Team", "description": "Establish a trained incident response team (CSIRT/CERT).", "weight": 5},
            "RES-03": {"title": "Incident Communication", "description": "Establish incident notification and communication procedures.", "weight": 4},
            "RES-04": {"title": "Business Continuity", "description": "Develop and test business continuity and disaster recovery plans.", "weight": 5},
            "RES-05": {"title": "Forensic Capability", "description": "Establish digital forensics and evidence handling capabilities.", "weight": 3},
            "RES-06": {"title": "Lessons Learned", "description": "Conduct post-incident reviews and implement improvements.", "weight": 4},
        }
    },
    "CII": {
        "id": "CII",
        "name": "Critical Information Infrastructure",
        "description": "Protects Ghana's critical information infrastructure and national assets.",
        "controls": {
            "CII-01": {"title": "CII Identification", "description": "Identify and classify critical information infrastructure assets.", "weight": 5},
            "CII-02": {"title": "CII Protection Standards", "description": "Implement enhanced protection standards for CII.", "weight": 5},
            "CII-03": {"title": "Sector Coordination", "description": "Establish sector-specific cybersecurity coordination mechanisms.", "weight": 4},
            "CII-04": {"title": "National Reporting", "description": "Report cybersecurity incidents to Ghana Cyber Security Authority.", "weight": 4},
        }
    }
}

ISO27002_DOMAINS = {
    "ORG": {
        "id": "ORG",
        "name": "Organizational Controls (Clause 5)",
        "description": "Controls related to organizational policies, roles, responsibilities, and management direction for information security.",
        "controls": {
            "5.1": {"title": "Policies for Information Security", "description": "Information security policy and topic-specific policies shall be defined, approved, published, and communicated.", "weight": 5},
            "5.2": {"title": "Information Security Roles", "description": "Information security roles and responsibilities shall be defined and allocated.", "weight": 5},
            "5.3": {"title": "Segregation of Duties", "description": "Conflicting duties and responsibilities shall be segregated.", "weight": 4},
            "5.4": {"title": "Management Responsibilities", "description": "Management shall require all personnel to apply information security per established policies.", "weight": 4},
            "5.5": {"title": "Contact with Authorities", "description": "Establish and maintain contact with relevant authorities.", "weight": 3},
            "5.6": {"title": "Contact with Special Interest Groups", "description": "Establish contacts with special interest groups and security forums.", "weight": 3},
            "5.7": {"title": "Threat Intelligence", "description": "Collect and analyze information relating to information security threats.", "weight": 4},
            "5.8": {"title": "Information Security in Project Management", "description": "Integrate information security into project management.", "weight": 3},
            "5.9": {"title": "Inventory of Information Assets", "description": "Develop and maintain an inventory of information and associated assets.", "weight": 5},
            "5.10": {"title": "Acceptable Use of Assets", "description": "Rules for acceptable use of information and assets shall be identified and documented.", "weight": 4},
            "5.11": {"title": "Return of Assets", "description": "Personnel shall return organizational assets upon termination.", "weight": 3},
            "5.12": {"title": "Classification of Information", "description": "Information shall be classified according to information security needs.", "weight": 4},
            "5.13": {"title": "Labelling of Information", "description": "Appropriate set of procedures for information labelling shall be developed.", "weight": 3},
            "5.14": {"title": "Information Transfer", "description": "Rules, procedures, or agreements for information transfer shall be in place.", "weight": 4},
            "5.15": {"title": "Access Control", "description": "Rules to control physical and logical access shall be established.", "weight": 5},
            "5.16": {"title": "Identity Management", "description": "Full lifecycle of identities shall be managed.", "weight": 4},
            "5.17": {"title": "Authentication Information", "description": "Allocation of authentication information shall be controlled.", "weight": 4},
            "5.18": {"title": "Access Rights", "description": "Access rights to information shall be provisioned, reviewed, modified, and removed.", "weight": 4},
            "5.19": {"title": "Information Security in Supplier Relationships", "description": "Processes to manage information security risks with suppliers.", "weight": 4},
            "5.20": {"title": "Addressing Security in Supplier Agreements", "description": "Relevant security requirements shall be established with each supplier.", "weight": 4},
            "5.21": {"title": "Managing Security in ICT Supply Chain", "description": "Processes to manage ICT supply chain security risks.", "weight": 3},
            "5.22": {"title": "Monitoring & Review of Supplier Services", "description": "Regularly monitor, review, and audit supplier service delivery.", "weight": 3},
            "5.23": {"title": "Information Security for Cloud Services", "description": "Processes for acquisition, use, management, and exit of cloud services.", "weight": 4},
            "5.24": {"title": "Incident Management Planning", "description": "Plan and prepare for managing information security incidents.", "weight": 5},
            "5.25": {"title": "Assessment and Decision on Events", "description": "Assess security events and decide if they are incidents.", "weight": 4},
            "5.26": {"title": "Response to Incidents", "description": "Information security incidents shall be responded to according to procedures.", "weight": 5},
            "5.27": {"title": "Learning from Incidents", "description": "Knowledge gained from incidents shall be used to strengthen controls.", "weight": 4},
            "5.28": {"title": "Collection of Evidence", "description": "Establish procedures for identification, collection, and preservation of evidence.", "weight": 3},
            "5.29": {"title": "Information Security during Disruption", "description": "Plan how to maintain security during disruption.", "weight": 4},
            "5.30": {"title": "ICT Readiness for Business Continuity", "description": "ICT readiness shall be planned, implemented, maintained, and tested.", "weight": 5},
            "5.31": {"title": "Legal, Statutory & Contractual Requirements", "description": "Identify and document requirements relevant to information security.", "weight": 4},
            "5.32": {"title": "Intellectual Property Rights", "description": "Implement appropriate procedures to protect intellectual property.", "weight": 3},
            "5.33": {"title": "Protection of Records", "description": "Records shall be protected from loss, destruction, and falsification.", "weight": 4},
            "5.34": {"title": "Privacy and Protection of PII", "description": "Ensure privacy and protection of personally identifiable information.", "weight": 5},
            "5.35": {"title": "Independent Review of Information Security", "description": "Approach to managing security shall be independently reviewed.", "weight": 4},
            "5.36": {"title": "Compliance with Policies and Standards", "description": "Compliance with security policy and standards shall be regularly reviewed.", "weight": 4},
            "5.37": {"title": "Documented Operating Procedures", "description": "Operating procedures for information processing facilities shall be documented.", "weight": 3},
        }
    },
    "PPL": {
        "id": "PPL",
        "name": "People Controls (Clause 6)",
        "description": "Controls related to personnel security, awareness, and training.",
        "controls": {
            "6.1": {"title": "Screening", "description": "Background verification checks on candidates shall be carried out.", "weight": 4},
            "6.2": {"title": "Terms and Conditions of Employment", "description": "Employment agreements shall state personnel's security responsibilities.", "weight": 4},
            "6.3": {"title": "Information Security Awareness & Training", "description": "Personnel shall receive appropriate security awareness education and training.", "weight": 5},
            "6.4": {"title": "Disciplinary Process", "description": "A disciplinary process shall be formalized for security policy violations.", "weight": 3},
            "6.5": {"title": "Responsibilities after Termination", "description": "Security responsibilities valid after termination shall be defined and enforced.", "weight": 3},
            "6.6": {"title": "Confidentiality or NDA", "description": "Confidentiality or non-disclosure agreements shall be identified and reviewed.", "weight": 4},
            "6.7": {"title": "Remote Working", "description": "Security measures shall be implemented for remote working.", "weight": 4},
            "6.8": {"title": "Information Security Event Reporting", "description": "Mechanism for personnel to report observed security events.", "weight": 4},
        }
    },
    "PHY": {
        "id": "PHY",
        "name": "Physical Controls (Clause 7)",
        "description": "Controls related to physical security of premises, equipment, and facilities.",
        "controls": {
            "7.1": {"title": "Physical Security Perimeters", "description": "Security perimeters shall be defined to protect areas with information.", "weight": 4},
            "7.2": {"title": "Physical Entry", "description": "Secure areas shall be protected by appropriate entry controls.", "weight": 4},
            "7.3": {"title": "Securing Offices, Rooms & Facilities", "description": "Physical security for offices, rooms, and facilities shall be designed.", "weight": 3},
            "7.4": {"title": "Physical Security Monitoring", "description": "Premises shall be continuously monitored for unauthorized access.", "weight": 4},
            "7.5": {"title": "Protecting against Physical & Environmental Threats", "description": "Protection against physical and environmental threats shall be designed.", "weight": 3},
            "7.6": {"title": "Working in Secure Areas", "description": "Security measures for working in secure areas shall be designed.", "weight": 3},
            "7.7": {"title": "Clear Desk and Clear Screen", "description": "Clear desk and clear screen rules shall be defined and enforced.", "weight": 3},
            "7.8": {"title": "Equipment Siting and Protection", "description": "Equipment shall be sited securely and protected.", "weight": 3},
            "7.9": {"title": "Security of Assets Off-Premises", "description": "Off-site assets shall be protected.", "weight": 3},
            "7.10": {"title": "Storage Media", "description": "Storage media shall be managed through lifecycle.", "weight": 4},
            "7.11": {"title": "Supporting Utilities", "description": "Information processing facilities shall be protected from power failures.", "weight": 3},
            "7.12": {"title": "Cabling Security", "description": "Cables carrying power and data shall be protected.", "weight": 3},
            "7.13": {"title": "Equipment Maintenance", "description": "Equipment shall be maintained correctly for availability and integrity.", "weight": 3},
            "7.14": {"title": "Secure Disposal or Re-use of Equipment", "description": "Items of equipment containing storage media shall be verified.", "weight": 4},
        }
    },
    "TEC": {
        "id": "TEC",
        "name": "Technological Controls (Clause 8)",
        "description": "Controls related to technological measures for information security.",
        "controls": {
            "8.1": {"title": "User Endpoint Devices", "description": "Information stored on, processed by, or accessible via user endpoint devices shall be protected.", "weight": 4},
            "8.2": {"title": "Privileged Access Rights", "description": "Allocation and use of privileged access rights shall be restricted and managed.", "weight": 5},
            "8.3": {"title": "Information Access Restriction", "description": "Access to information shall be restricted in accordance with access control policy.", "weight": 5},
            "8.4": {"title": "Access to Source Code", "description": "Read and write access to source code and development tools shall be managed.", "weight": 3},
            "8.5": {"title": "Secure Authentication", "description": "Secure authentication technologies and procedures shall be implemented.", "weight": 5},
            "8.6": {"title": "Capacity Management", "description": "Use of resources shall be monitored and adjusted.", "weight": 3},
            "8.7": {"title": "Protection against Malware", "description": "Protection against malware shall be implemented.", "weight": 5},
            "8.8": {"title": "Management of Technical Vulnerabilities", "description": "Information about technical vulnerabilities shall be obtained and managed.", "weight": 5},
            "8.9": {"title": "Configuration Management", "description": "Configurations shall be established, documented, implemented, and monitored.", "weight": 4},
            "8.10": {"title": "Information Deletion", "description": "Information stored in systems and devices shall be deleted when no longer required.", "weight": 3},
            "8.11": {"title": "Data Masking", "description": "Data masking shall be used in accordance with access control policy.", "weight": 3},
            "8.12": {"title": "Data Leakage Prevention", "description": "Data leakage prevention measures shall be applied.", "weight": 4},
            "8.13": {"title": "Information Backup", "description": "Backup copies of information shall be maintained and tested.", "weight": 5},
            "8.14": {"title": "Redundancy of Information Processing Facilities", "description": "Information processing facilities shall be implemented with redundancy.", "weight": 4},
            "8.15": {"title": "Logging", "description": "Logs recording activities, exceptions, and events shall be produced and protected.", "weight": 5},
            "8.16": {"title": "Monitoring Activities", "description": "Networks, systems, and applications shall be monitored for anomalous behavior.", "weight": 5},
            "8.17": {"title": "Clock Synchronization", "description": "Clocks of information processing systems shall be synchronized.", "weight": 3},
            "8.18": {"title": "Use of Privileged Utility Programs", "description": "Use of utility programs capable of overriding controls shall be restricted.", "weight": 3},
            "8.19": {"title": "Installation of Software on Operational Systems", "description": "Procedures to control installation of software on operational systems.", "weight": 4},
            "8.20": {"title": "Networks Security", "description": "Networks and network devices shall be secured and managed.", "weight": 5},
            "8.21": {"title": "Security of Network Services", "description": "Security mechanisms and service levels of network services shall be identified.", "weight": 4},
            "8.22": {"title": "Segregation of Networks", "description": "Groups of information services and systems shall be segregated.", "weight": 4},
            "8.23": {"title": "Web Filtering", "description": "Access to external websites shall be managed.", "weight": 3},
            "8.24": {"title": "Use of Cryptography", "description": "Rules for the effective use of cryptography shall be defined.", "weight": 4},
            "8.25": {"title": "Secure Development Life Cycle", "description": "Rules for secure development of software and systems shall be established.", "weight": 4},
            "8.26": {"title": "Application Security Requirements", "description": "Information security requirements shall be identified when developing applications.", "weight": 4},
            "8.27": {"title": "Secure System Architecture & Engineering Principles", "description": "Principles for engineering secure systems shall be established.", "weight": 4},
            "8.28": {"title": "Secure Coding", "description": "Secure coding principles shall be applied.", "weight": 4},
            "8.29": {"title": "Security Testing in Development & Acceptance", "description": "Security testing processes shall be defined in the development lifecycle.", "weight": 4},
            "8.30": {"title": "Outsourced Development", "description": "The organization shall direct and monitor outsourced development activity.", "weight": 3},
            "8.31": {"title": "Separation of Development, Test & Production Environments", "description": "Development, testing, and production environments shall be separated.", "weight": 4},
            "8.32": {"title": "Change Management", "description": "Changes to information processing facilities shall be subject to change management.", "weight": 4},
            "8.33": {"title": "Test Information", "description": "Test information shall be appropriately selected, protected, and managed.", "weight": 3},
            "8.34": {"title": "Protection of Information during Audit Testing", "description": "Audit tests and activities involving operational systems shall be planned.", "weight": 3},
        }
    }
}

# Control Mapping: Ghana NCF -> ISO 27002
CONTROL_MAPPING = {
    "GOV-01": {"iso_controls": ["5.1", "5.2"], "alignment": "strong", "notes": "Ghana's cybersecurity policy requirement directly maps to ISO 27002 policies for information security."},
    "GOV-02": {"iso_controls": ["5.2", "5.3", "5.4"], "alignment": "strong", "notes": "Governance structure aligns well with ISO roles, segregation of duties, and management responsibilities."},
    "GOV-03": {"iso_controls": ["5.7", "5.31"], "alignment": "moderate", "notes": "Risk management framework partially maps; ISO 27002 focuses more on threat intelligence and legal requirements."},
    "GOV-04": {"iso_controls": ["5.31", "5.32", "5.34", "5.36"], "alignment": "strong", "notes": "Regulatory compliance maps to ISO legal, privacy, and compliance controls."},
    "GOV-05": {"iso_controls": ["5.4"], "alignment": "partial", "notes": "Resource allocation is implied in ISO but not explicitly addressed as a standalone control."},
    "GOV-06": {"iso_controls": ["5.4", "5.35"], "alignment": "moderate", "notes": "Board oversight maps partially to management responsibilities and independent review."},
    "GOV-07": {"iso_controls": ["5.35", "5.36"], "alignment": "moderate", "notes": "Performance metrics align with independent review and compliance monitoring."},
    "IDN-01": {"iso_controls": ["5.9", "5.10", "5.11", "5.12"], "alignment": "strong", "notes": "Asset inventory directly maps to ISO asset management controls."},
    "IDN-02": {"iso_controls": ["5.7", "8.8"], "alignment": "strong", "notes": "Risk assessment aligns with threat intelligence and vulnerability management."},
    "IDN-03": {"iso_controls": ["5.7"], "alignment": "strong", "notes": "Threat intelligence has direct mapping in ISO 27002:2022."},
    "IDN-04": {"iso_controls": ["8.8", "8.7"], "alignment": "strong", "notes": "Vulnerability management directly maps to ISO technical vulnerability management."},
    "IDN-05": {"iso_controls": ["5.29", "5.30"], "alignment": "strong", "notes": "BIA maps to ISO continuity and ICT readiness controls."},
    "IDN-06": {"iso_controls": ["5.19", "5.20", "5.21", "5.22", "5.23"], "alignment": "strong", "notes": "Supply chain risk has comprehensive mapping in ISO 27002."},
    "PRO-01": {"iso_controls": ["5.15", "5.16", "5.17", "5.18", "8.2", "8.3"], "alignment": "strong", "notes": "Access control has extensive mapping across ISO organizational and technical controls."},
    "PRO-02": {"iso_controls": ["5.12", "5.13", "5.14", "5.34", "8.10", "8.11", "8.12"], "alignment": "strong", "notes": "Data protection maps to classification, labelling, transfer, privacy, and DLP controls."},
    "PRO-03": {"iso_controls": ["8.20", "8.21", "8.22", "8.23"], "alignment": "strong", "notes": "Network security has direct mapping to ISO network controls."},
    "PRO-04": {"iso_controls": ["8.1", "8.7"], "alignment": "strong", "notes": "Endpoint protection maps to user endpoint devices and malware protection."},
    "PRO-05": {"iso_controls": ["6.3"], "alignment": "strong", "notes": "Security awareness training has direct mapping."},
    "PRO-06": {"iso_controls": ["8.24"], "alignment": "strong", "notes": "Cryptographic controls have direct mapping."},
    "PRO-07": {"iso_controls": ["7.1", "7.2", "7.3", "7.4", "7.5", "7.6", "7.7", "7.8"], "alignment": "strong", "notes": "Physical security maps extensively to ISO physical controls."},
    "PRO-08": {"iso_controls": ["8.9", "8.19"], "alignment": "strong", "notes": "Secure configuration maps to ISO configuration management and software installation."},
    "PRO-09": {"iso_controls": ["8.25", "8.26", "8.27", "8.28", "8.29", "8.31"], "alignment": "strong", "notes": "Application security maps comprehensively to ISO SDLC controls."},
    "DET-01": {"iso_controls": ["8.15", "8.16"], "alignment": "strong", "notes": "Security monitoring directly maps to ISO logging and monitoring activities."},
    "DET-02": {"iso_controls": ["8.15", "8.17"], "alignment": "strong", "notes": "Log management maps to ISO logging and clock synchronization."},
    "DET-03": {"iso_controls": ["8.16"], "alignment": "strong", "notes": "Anomaly detection maps to ISO monitoring activities."},
    "DET-04": {"iso_controls": ["5.7", "8.7", "8.16"], "alignment": "strong", "notes": "Threat detection maps to threat intelligence, malware protection, and monitoring."},
    "DET-05": {"iso_controls": ["5.35", "5.36", "8.34"], "alignment": "strong", "notes": "Security auditing maps to ISO review and audit controls."},
    "RES-01": {"iso_controls": ["5.24", "5.25", "5.26"], "alignment": "strong", "notes": "Incident response plan directly maps to ISO incident management controls."},
    "RES-02": {"iso_controls": ["5.24", "5.26"], "alignment": "moderate", "notes": "CSIRT requirement is Ghana-specific; ISO addresses incident response capabilities."},
    "RES-03": {"iso_controls": ["5.5", "5.26", "6.8"], "alignment": "strong", "notes": "Incident communication maps to ISO contact with authorities and event reporting."},
    "RES-04": {"iso_controls": ["5.29", "5.30"], "alignment": "strong", "notes": "Business continuity has direct mapping."},
    "RES-05": {"iso_controls": ["5.28"], "alignment": "strong", "notes": "Forensic capability maps to ISO evidence collection."},
    "RES-06": {"iso_controls": ["5.27"], "alignment": "strong", "notes": "Lessons learned directly maps to ISO learning from incidents."},
    "CII-01": {"iso_controls": ["5.9", "5.12"], "alignment": "partial", "notes": "CII identification is Ghana-specific; ISO covers asset inventory and classification generally."},
    "CII-02": {"iso_controls": ["5.1", "8.9"], "alignment": "partial", "notes": "CII-specific protection standards are Ghana-specific; ISO provides general security policies."},
    "CII-03": {"iso_controls": ["5.5", "5.6"], "alignment": "partial", "notes": "Sector coordination is Ghana-specific; ISO covers contact with authorities and special interest groups."},
    "CII-04": {"iso_controls": ["5.5", "5.24", "6.8"], "alignment": "moderate", "notes": "National reporting to Ghana CSA is country-specific; ISO covers general incident reporting."},
}

# Gap Analysis Data
GAP_ANALYSIS = {
    "ghana_unique": [
        {"control": "CII-01 to CII-04", "description": "Critical Information Infrastructure controls are unique to Ghana's framework, reflecting national security priorities.", "significance": "high"},
        {"control": "GOV-04", "description": "Specific reference to Ghana's Data Protection Act 2012 and Cybersecurity Act 2020.", "significance": "high"},
        {"control": "CII-04", "description": "Mandatory reporting to Ghana Cyber Security Authority (CSA) is a national regulatory requirement.", "significance": "high"},
        {"control": "GOV-05", "description": "Explicit resource allocation requirements are more pronounced in Ghana's framework.", "significance": "medium"},
    ],
    "iso_unique": [
        {"control": "7.x Physical Controls", "description": "ISO 27002 provides more granular physical security controls (14 controls vs Ghana's single PRO-07).", "significance": "medium"},
        {"control": "6.x People Controls", "description": "ISO 27002 has dedicated people controls (screening, NDA, remote working) that Ghana addresses less specifically.", "significance": "medium"},
        {"control": "8.4, 8.6, 8.10-8.11", "description": "Source code access, capacity management, information deletion, and data masking are ISO-specific.", "significance": "low"},
        {"control": "5.8, 5.32, 5.33", "description": "Project management security, intellectual property, and records protection are more detailed in ISO.", "significance": "low"},
        {"control": "8.31, 8.33", "description": "Environment separation and test information management are ISO-specific technical controls.", "significance": "medium"},
    ],
    "alignment_summary": {
        "strong": 27,
        "moderate": 5,
        "partial": 5,
        "total_mapped": 37,
        "overall_alignment_percentage": 78.5
    }
}

# Maturity Levels
MATURITY_LEVELS = {
    0: {"label": "Non-Existent", "description": "No awareness or implementation of the control.", "color": "#DC2626"},
    1: {"label": "Initial/Ad-hoc", "description": "Processes are ad-hoc and disorganized. Success depends on individual effort.", "color": "#EA580C"},
    2: {"label": "Developing", "description": "Processes are planned and tracked. Some documentation exists.", "color": "#D97706"},
    3: {"label": "Defined", "description": "Processes are documented, standardized, and integrated into standard practices.", "color": "#CA8A04"},
    4: {"label": "Managed", "description": "Processes are measured and controlled. Quantitative objectives are established.", "color": "#65A30D"},
    5: {"label": "Optimizing", "description": "Continuous improvement is enabled by quantitative feedback and innovative practices.", "color": "#16A34A"},
}

# In-memory storage for assessments
assessments_db = {}

def calculate_domain_score(responses, domain_id, framework="ghana"):
    """Calculate the compliance score for a domain"""
    if framework == "ghana":
        controls = GHANA_NCF_DOMAINS.get(domain_id, {}).get("controls", {})
    else:
        controls = ISO27002_DOMAINS.get(domain_id, {}).get("controls", {})

    if not controls:
        return 0, 0, 0

    total_weighted = 0
    achieved_weighted = 0
    max_possible = 0

    for ctrl_id, ctrl_info in controls.items():
        weight = ctrl_info["weight"]
        maturity = responses.get(ctrl_id, 0)
        max_possible += weight * 5
        achieved_weighted += weight * maturity
        total_weighted += weight

    score = (achieved_weighted / max_possible * 100) if max_possible > 0 else 0
    avg_maturity = achieved_weighted / total_weighted if total_weighted > 0 else 0

    return round(score, 1), round(avg_maturity, 2), max_possible


def generate_recommendations(responses, framework="ghana"):
    """Generate actionable recommendations based on assessment"""
    recommendations = []

    if framework == "ghana":
        domains = GHANA_NCF_DOMAINS
    else:
        domains = ISO27002_DOMAINS

    for domain_id, domain_info in domains.items():
        for ctrl_id, ctrl_info in domain_info["controls"].items():
            maturity = responses.get(ctrl_id, 0)
            weight = ctrl_info["weight"]
            priority = "Critical" if weight >= 5 and maturity <= 1 else \
                       "High" if weight >= 4 and maturity <= 2 else \
                       "Medium" if maturity <= 2 else \
                       "Low" if maturity <= 3 else "Informational"

            if maturity < 4:
                rec = {
                    "control_id": ctrl_id,
                    "control_title": ctrl_info["title"],
                    "domain": domain_info["name"],
                    "current_maturity": maturity,
                    "target_maturity": min(maturity + 2, 5),
                    "priority": priority,
                    "weight": weight,
                    "recommendation": get_recommendation_text(ctrl_id, ctrl_info, maturity)
                }
                recommendations.append(rec)

    # Sort by priority
    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    recommendations.sort(key=lambda x: (priority_order.get(x["priority"], 5), -x["weight"]))

    return recommendations


def get_recommendation_text(ctrl_id, ctrl_info, maturity):
    """Generate specific recommendation text"""
    title = ctrl_info["title"]
    if maturity == 0:
        return f"Immediately initiate the implementation of {title}. Develop a formal policy and assign responsibility. This control has no current implementation and requires urgent attention."
    elif maturity == 1:
        return f"Formalize the ad-hoc processes for {title}. Document procedures, assign roles, and establish a baseline. Move from reactive to planned approach."
    elif maturity == 2:
        return f"Standardize and document {title} processes across the organization. Ensure consistent application and conduct initial training."
    elif maturity == 3:
        return f"Implement measurement and monitoring for {title}. Establish KPIs, conduct regular reviews, and ensure management reporting is in place."
    else:
        return f"Focus on continuous improvement for {title}. Implement automation, benchmarking, and advanced optimization techniques."


class ComplianceAPIHandler(SimpleHTTPRequestHandler):
    """HTTP Request Handler for the Compliance API"""

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        if self.path == '/api/frameworks/ghana':
            self.send_json_response(GHANA_NCF_DOMAINS)
        elif self.path == '/api/frameworks/iso27002':
            self.send_json_response(ISO27002_DOMAINS)
        elif self.path == '/api/mapping':
            self.send_json_response(CONTROL_MAPPING)
        elif self.path == '/api/gaps':
            self.send_json_response(GAP_ANALYSIS)
        elif self.path == '/api/maturity-levels':
            self.send_json_response(MATURITY_LEVELS)
        elif self.path.startswith('/api/assessment/'):
            assessment_id = self.path.split('/')[-1]
            if assessment_id in assessments_db:
                self.send_json_response(assessments_db[assessment_id])
            else:
                self.send_error_response(404, "Assessment not found")
        elif self.path == '/' or self.path == '/index.html':
            self.path = '/index.html'
            return SimpleHTTPRequestHandler.do_GET(self)
        else:
            return SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self.send_error_response(400, "Invalid JSON")
            return

        if self.path == '/api/assess':
            result = self.process_assessment(data)
            self.send_json_response(result)
        elif self.path == '/api/report':
            result = self.generate_report(data)
            self.send_json_response(result)
        else:
            self.send_error_response(404, "Endpoint not found")

    def process_assessment(self, data):
        """Process a compliance assessment submission"""
        assessment_id = str(uuid.uuid4())[:8].upper()
        org_name = data.get("organization", "Unknown Organization")
        org_sector = data.get("sector", "General")
        ghana_responses = data.get("ghana_responses", {})
        iso_responses = data.get("iso_responses", {})

        # Calculate Ghana NCF scores
        ghana_domain_scores = {}
        ghana_total_score = 0
        ghana_domain_count = 0
        for domain_id in GHANA_NCF_DOMAINS:
            score, avg_mat, max_p = calculate_domain_score(ghana_responses, domain_id, "ghana")
            ghana_domain_scores[domain_id] = {
                "domain_name": GHANA_NCF_DOMAINS[domain_id]["name"],
                "score": score,
                "average_maturity": avg_mat,
                "control_count": len(GHANA_NCF_DOMAINS[domain_id]["controls"])
            }
            ghana_total_score += score
            ghana_domain_count += 1

        # Calculate ISO 27002 scores
        iso_domain_scores = {}
        iso_total_score = 0
        iso_domain_count = 0
        for domain_id in ISO27002_DOMAINS:
            score, avg_mat, max_p = calculate_domain_score(iso_responses, domain_id, "iso")
            iso_domain_scores[domain_id] = {
                "domain_name": ISO27002_DOMAINS[domain_id]["name"],
                "score": score,
                "average_maturity": avg_mat,
                "control_count": len(ISO27002_DOMAINS[domain_id]["controls"])
            }
            iso_total_score += score
            iso_domain_count += 1

        ghana_overall = round(ghana_total_score / ghana_domain_count, 1) if ghana_domain_count > 0 else 0
        iso_overall = round(iso_total_score / iso_domain_count, 1) if iso_domain_count > 0 else 0

        # Cross-framework alignment
        alignment_scores = {}
        for ghana_ctrl, mapping in CONTROL_MAPPING.items():
            ghana_mat = ghana_responses.get(ghana_ctrl, 0)
            iso_mats = [iso_responses.get(ic, 0) for ic in mapping["iso_controls"]]
            avg_iso_mat = sum(iso_mats) / len(iso_mats) if iso_mats else 0
            gap = abs(ghana_mat - avg_iso_mat)
            alignment_scores[ghana_ctrl] = {
                "ghana_maturity": ghana_mat,
                "iso_average_maturity": round(avg_iso_mat, 2),
                "gap": round(gap, 2),
                "alignment_type": mapping["alignment"],
                "iso_controls": mapping["iso_controls"],
                "notes": mapping["notes"]
            }

        # Recommendations
        ghana_recs = generate_recommendations(ghana_responses, "ghana")
        iso_recs = generate_recommendations(iso_responses, "iso")

        # Compliance level determination
        def get_compliance_level(score):
            if score >= 80: return "Highly Compliant"
            elif score >= 60: return "Substantially Compliant"
            elif score >= 40: return "Partially Compliant"
            elif score >= 20: return "Minimally Compliant"
            else: return "Non-Compliant"

        result = {
            "assessment_id": assessment_id,
            "organization": org_name,
            "sector": org_sector,
            "timestamp": datetime.now().isoformat(),
            "ghana_ncf": {
                "overall_score": ghana_overall,
                "compliance_level": get_compliance_level(ghana_overall),
                "domain_scores": ghana_domain_scores,
                "recommendations": ghana_recs[:15]
            },
            "iso27002": {
                "overall_score": iso_overall,
                "compliance_level": get_compliance_level(iso_overall),
                "domain_scores": iso_domain_scores,
                "recommendations": iso_recs[:15]
            },
            "cross_framework": {
                "alignment_scores": alignment_scores,
                "overall_alignment": round((ghana_overall + iso_overall) / 2, 1),
                "gap_analysis": GAP_ANALYSIS
            }
        }

        assessments_db[assessment_id] = result
        return result

    def generate_report(self, data):
        """Generate a detailed compliance report"""
        assessment_id = data.get("assessment_id", "")
        if assessment_id in assessments_db:
            assessment = assessments_db[assessment_id]
            report = {
                "report_id": "RPT-" + str(uuid.uuid4())[:8].upper(),
                "generated_at": datetime.now().isoformat(),
                "assessment": assessment,
                "executive_summary": self.generate_executive_summary(assessment),
                "detailed_findings": self.generate_findings(assessment),
            }
            return report
        return {"error": "Assessment not found"}

    def generate_executive_summary(self, assessment):
        org = assessment["organization"]
        ghana_score = assessment["ghana_ncf"]["overall_score"]
        iso_score = assessment["iso27002"]["overall_score"]
        alignment = assessment["cross_framework"]["overall_alignment"]

        return {
            "organization": org,
            "ghana_ncf_score": ghana_score,
            "ghana_ncf_level": assessment["ghana_ncf"]["compliance_level"],
            "iso27002_score": iso_score,
            "iso27002_level": assessment["iso27002"]["compliance_level"],
            "overall_alignment": alignment,
            "key_findings": [
                f"{org} achieves {ghana_score}% compliance with Ghana's National Cybersecurity Framework.",
                f"{org} achieves {iso_score}% compliance with ISO/IEC 27002:2022 controls.",
                f"Cross-framework alignment stands at {alignment}%.",
                f"{'Strong' if alignment >= 70 else 'Moderate' if alignment >= 50 else 'Weak'} alignment exists between the two frameworks for this organization.",
            ]
        }

    def generate_findings(self, assessment):
        findings = []
        # Ghana NCF findings
        for domain_id, scores in assessment["ghana_ncf"]["domain_scores"].items():
            status = "Pass" if scores["score"] >= 60 else "Needs Improvement" if scores["score"] >= 40 else "Fail"
            findings.append({
                "framework": "Ghana NCF",
                "domain": scores["domain_name"],
                "score": scores["score"],
                "status": status,
                "average_maturity": scores["average_maturity"]
            })

        # ISO 27002 findings
        for domain_id, scores in assessment["iso27002"]["domain_scores"].items():
            status = "Pass" if scores["score"] >= 60 else "Needs Improvement" if scores["score"] >= 40 else "Fail"
            findings.append({
                "framework": "ISO/IEC 27002",
                "domain": scores["domain_name"],
                "score": scores["score"],
                "status": status,
                "average_maturity": scores["average_maturity"]
            })

        return findings

    def send_json_response(self, data, status=200):
        response = json.dumps(data, indent=2)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response.encode())

    def send_error_response(self, status, message):
        self.send_json_response({"error": message}, status)

    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")


def run_server(port=8000):
    server = HTTPServer(('0.0.0.0', port), ComplianceAPIHandler)
    print("=" * 65)
    print("  Ghana NCF vs ISO/IEC 27002 Compliance Measurement System")
    print("=" * 65)
    print(f"  Server running at: http://localhost:{port}")
    print(f"  API endpoints:")
    print(f"    GET  /api/frameworks/ghana   - Ghana NCF controls")
    print(f"    GET  /api/frameworks/iso27002 - ISO 27002 controls")
    print(f"    GET  /api/mapping            - Control mapping")
    print(f"    GET  /api/gaps               - Gap analysis")
    print(f"    GET  /api/maturity-levels    - Maturity level definitions")
    print(f"    POST /api/assess             - Submit assessment")
    print(f"    POST /api/report             - Generate report")
    print("=" * 65)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()


if __name__ == '__main__':
    run_server()
