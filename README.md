# 🛡️ GH-CYBER**COMPLY**

### Ghana NCF vs ISO/IEC 27002 Automated Compliance Measurement System

An automated web-based compliance measurement system that performs a structured comparative evaluation between **Ghana's National Cybersecurity Framework (NCF)** and **ISO/IEC 27002:2022** security controls. It assesses and quantifies organizational alignment levels through maturity-based scoring, control mapping, gap analysis, and actionable compliance reporting.

---

![Python](https://img.shields.io/badge/Backend-Python%203.x-blue?logo=python&logoColor=white)
![HTML5](https://img.shields.io/badge/Frontend-HTML5-orange?logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/Styling-CSS3-blue?logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/Logic-JavaScript-yellow?logo=javascript&logoColor=white)
![Chart.js](https://img.shields.io/badge/Charts-Chart.js-pink?logo=chartdotjs&logoColor=white)

---

## 📋 Table of Contents

- [About the Project](#about-the-project)
- [Research Objectives](#research-objectives)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Pages Overview](#pages-overview)
- [Scoring Methodology](#scoring-methodology)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [API Endpoints](#api-endpoints)
- [Screenshots](#screenshots)
- [Project Structure](#project-structure)
- [Contributing](#contributing)

---

## 📖 About the Project

This project addresses the critical need for a structured and automated approach to evaluating cybersecurity compliance in Ghana. Organizations operating in Ghana must align with both the **Ghana National Cybersecurity Framework (NCF)** and international standards like **ISO/IEC 27002:2022**, but currently lack tools to measure and compare their compliance levels across both frameworks simultaneously.

**GH-CYBERCOMPLY** bridges this gap by providing:
- A detailed **control mapping** between both frameworks
- A **maturity-based assessment** system using the Capability Maturity Model (CMM Levels 0–5)
- An automated **scoring engine** with weighted compliance calculations
- **Visual dashboards**, charts, and exportable reports
- A **gap analysis** identifying framework-unique controls and structural differences

---

## 🎯 Research Objectives

### Primary Objective
To conduct a structured comparative evaluation between Ghana's National Cybersecurity Framework and ISO/IEC 27002 security controls, and to design and implement an automated compliance measurement system that assesses and quantifies alignment levels for organizations operating within Ghana.

### Specific Objectives

1. **Analyze and Compare** — Review the structures of Ghana's NCF and ISO/IEC 27002, perform detailed control mapping to identify similarities, differences, and gaps.

2. **Develop a Compliance Measurement Model** — Build an automated web-based system that evaluates and scores organizational alignment with both frameworks using maturity-based scoring.

3. **Test, Validate, and Report** — Generate compliance reports that provide actionable recommendations for improving cybersecurity alignment and regulatory compliance.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **📊 Interactive Dashboard** | Overview statistics, research methodology, maturity model explanation, and framework summaries |
| **🔗 Control Mapping** | 47 cross-framework mappings with alignment levels (Strong/Moderate/Partial) and searchable filters |
| **📝 Assessment Wizard** | 3-step assessment flow covering organization info, 37 Ghana NCF controls, and 93 ISO 27002 controls |
| **📈 Results & Reports** | Radar charts, bar comparisons, domain breakdowns, prioritized recommendations with severity levels |
| **🔍 Gap Analysis** | Identifies Ghana-unique controls, ISO-unique controls, structural differences, and key insights |
| **🖨️ Export & Print** | Print-friendly reports and JSON data export |
| **📱 Responsive Design** | Mobile-first design with slide-in navigation drawer |
| **🎨 Modern UI** | Glassmorphism effects, animated backgrounds, scroll-reveal animations, and hover effects |
| **⚡ Demo Mode** | One-click demo data fill for quick testing |
| **💾 Local Storage** | Assessment data persists between pages using browser localStorage |

---

## 🏗️ System Architecture

```
┌──────────────────────────────────────────────────┐
│                    Frontend                       │
│         HTML5 / CSS3 / JavaScript                 │
│                                                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │Dashboard │ │ Mapping  │ │Assessment│         │
│  │  Page    │ │  Page    │ │  Page    │         │
│  └──────────┘ └──────────┘ └──────────┘         │
│  ┌──────────┐ ┌──────────┐                       │
│  │ Results  │ │   Gap    │   Chart.js            │
│  │  Page    │ │ Analysis │   localStorage        │
│  └──────────┘ └──────────┘                       │
└────────────────────┬─────────────────────────────┘
                     │ HTTP / REST API
┌────────────────────┴─────────────────────────────┐
│                  Backend                          │
│              Python 3.x                           │
│                                                   │
│  ┌────────────────────────────────────────┐       │
│  │         server.py                      │       │
│  │  • Framework Data (NCF + ISO 27002)    │       │
│  │  • Control Mapping Engine              │       │
│  │  • Scoring & Assessment Engine         │       │
│  │  • Gap Analysis Engine                 │       │
│  │  • Report Generation                   │       │
│  │  • Static File Server                  │       │
│  └────────────────────────────────────────┘       │
└──────────────────────────────────────────────────┘
```

---

## 📄 Pages Overview

### 1. Dashboard (`index.html`)
The home page providing an executive overview of the system including:
- Key statistics (37 NCF controls, 93 ISO controls, 47 mappings, 130 total controls)
- Research objectives and methodology
- CMM Maturity Model explanation (Levels 0–5)
- Scoring formula breakdown
- Framework overview cards
- Quick navigation actions

### 2. Control Mapping (`mapping.html`)
Interactive cross-framework mapping table featuring:
- All 47 control mappings between Ghana NCF and ISO 27002
- Alignment level badges (Strong 🟢 / Moderate 🟡 / Partial 🟠)
- Filter buttons by alignment type
- Live search functionality
- Alignment distribution statistics

### 3. Assessment (`assessment.html`)
Three-step assessment wizard:
- **Step 1** — Organization information (name, sector, size, contact)
- **Step 2** — Ghana NCF maturity assessment (37 controls across 6 domains)
- **Step 3** — ISO 27002 maturity assessment (93 controls across 4 themes)
- CMM-based sliders (0–5) with labeled maturity levels
- Progress tracking bar
- Demo Fill button for quick testing

### 4. Results (`results.html`)
Comprehensive compliance report including:
- Executive summary with overall percentage scores
- Radar charts for each framework
- Horizontal bar comparison chart
- Cross-framework alignment visualization
- Domain/theme breakdown with progress bars
- Prioritized recommendations table (Critical/High/Medium/Low)
- Detailed scores table
- Print and JSON export functionality

### 5. Gap Analysis (`gaps.html`)
Framework comparison and gap identification:
- 5 Ghana-unique controls not in ISO 27002
- 8 ISO 27002-unique controls not in Ghana NCF
- Structural comparison table (8 aspects)
- Key insights and observations
- Organizational recommendations

---

## 📐 Scoring Methodology

### Capability Maturity Model (CMM) — Levels 0 to 5

| Level | Name | Description |
|-------|------|-------------|
| **0** | Non-Existent | No process or control exists |
| **1** | Initial | Ad-hoc, unstructured processes |
| **2** | Developing | Basic processes in place but inconsistent |
| **3** | Defined | Standardized and documented processes |
| **4** | Managed | Measured, monitored, and controlled |
| **5** | Optimized | Continuous improvement and optimization |

### Compliance Score Formula

```
Compliance Score (%) = (Σ (Control Score × Weight)) / (Max Possible Score) × 100
```

Where:
- **Control Score** = Maturity level (0–5) assigned during assessment
- **Weight** = Importance factor based on control criticality
- **Max Possible Score** = 5 × Σ Weights (if all controls were at Level 5)

### Alignment Classification

| Score Range | Classification |
|-------------|---------------|
| 80–100% | **Excellent** — Strong alignment with frameworks |
| 60–79% | **Good** — Adequate alignment with room for improvement |
| 40–59% | **Fair** — Significant gaps requiring attention |
| 0–39% | **Poor** — Major deficiencies, urgent action needed |

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| **Frontend** | HTML5, CSS3, JavaScript (Vanilla) |
| **Backend** | Python 3.x (http.server, built-in libraries) |
| **Charts** | Chart.js (via CDN) |
| **Styling** | Custom CSS with CSS Variables, Glassmorphism |
| **Data Storage** | Browser localStorage (client-side), In-memory (server-side) |
| **API Format** | RESTful JSON |

> **Note:** No frameworks like React, Vue, Vite, or Node.js are used. The system runs entirely on vanilla HTML/CSS/JS and Python's built-in HTTP server.

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.6+** installed on your machine
- A modern web browser (Chrome, Firefox, Edge, Safari)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/gh-cybercomply.git
   cd gh-cybercomply
   ```

2. **Start the backend server**
   ```bash
   python server.py
   ```

3. **Open your browser**
   ```
   http://localhost:8000
   ```

That's it! No dependencies to install, no build steps required.

### Standalone Mode (No Backend)

The frontend pages can also function without the Python backend. Simply open `index.html` directly in a browser. Assessment scoring and data processing will run entirely in JavaScript using localStorage.

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/frameworks/ghana` | Returns all 37 Ghana NCF controls grouped by domain |
| `GET` | `/api/frameworks/iso27002` | Returns all 93 ISO 27002 controls grouped by theme |
| `GET` | `/api/mapping` | Returns 47 cross-framework control mappings |
| `GET` | `/api/gaps` | Returns gap analysis data (unique controls, structural comparison) |
| `POST` | `/api/assess` | Submits assessment data and returns calculated scores |
| `POST` | `/api/report` | Generates a detailed compliance report with recommendations |

### Example: Submit Assessment
```bash
curl -X POST http://localhost:8000/api/assess \
  -H "Content-Type: application/json" \
  -d '{
    "organization": "Example Corp",
    "sector": "Financial Services",
    "ghana_scores": {"GH-GOV-001": 3, "GH-GOV-002": 4},
    "iso_scores": {"ISO-5.1": 3, "ISO-5.2": 4}
  }'
```

---

## 📸 Screenshots

> _Add screenshots of your deployed application here._

| Dashboard | Control Mapping |
|-----------|----------------|
| ![Dashboard](screenshots/dashboard.png) | ![Mapping](screenshots/mapping.png) |

| Assessment | Results |
|------------|---------|
| ![Assessment](screenshots/assessment.png) | ![Results](screenshots/results.png) |

---

## 📁 Project Structure

```
gh-cybercomply/
│
├── index.html          # Dashboard — home page with stats and overview
├── mapping.html        # Control Mapping — cross-framework mapping table
├── assessment.html     # Assessment — 3-step maturity assessment wizard
├── results.html        # Results — compliance scores, charts, and reports
├── gaps.html           # Gap Analysis — framework gaps and recommendations
├── server.py           # Python backend — REST API and static file server
├── README.md           # Project documentation (this file)
│
└── screenshots/        # (Optional) Application screenshots
    ├── dashboard.png
    ├── mapping.png
    ├── assessment.png
    └── results.png
```

---

## 🤝 Contributing

Contributions are welcome! If you'd like to improve this project:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/your-feature`)
3. **Commit** your changes (`git commit -m 'Add your feature'`)
4. **Push** to the branch (`git push origin feature/your-feature`)
5. **Open** a Pull Request

### Areas for Contribution
- Adding more controls to either framework
- Improving the scoring algorithm
- Adding PDF report export
- Database integration for persistent storage
- User authentication and multi-tenant support
- Additional framework support (e.g., NIST CSF, COBIT)

---

## 👤 Author

**Your Name**

- GitHub: [@yourusername](https://github.com/yourusername)

---

## 🙏 Acknowledgments

- **Cyber Security Authority of Ghana** — For the National Cybersecurity Framework
- **ISO/IEC** — For the 27002:2022 Information Security Controls standard
- **Chart.js** — For the charting library
- **CMM Institute** — For the Capability Maturity Model methodology

---

<p align="center">
  <strong>🛡️ GH-CYBERCOMPLY</strong><br>
  <em>Bridging Ghana's Cybersecurity Framework with International Standards</em>
</p>
