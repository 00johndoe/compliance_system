# 🛡️ GH-CYBERCOMPLY

### Ghana NCF vs ISO/IEC 27002 Automated Compliance Measurement System

An automated web-based compliance measurement system that performs a structured comparative evaluation between **Ghana's National Cybersecurity Framework (NCF)** and **ISO/IEC 27002:2022** security controls. It assesses and quantifies alignment levels for organizations operating within Ghana.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Objectives](#objectives)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Installation & Setup](#installation--setup)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Screenshots](#screenshots)
- [Contributing](#contributing)

---

## 🔍 Overview

This system was developed as part of a research study to conduct a **structured comparative evaluation** between Ghana's National Cybersecurity Framework and ISO/IEC 27002 security controls. It provides an automated compliance measurement platform that evaluates and scores organizational alignment with both frameworks using a **Capability Maturity Model (CMM)** based scoring methodology.

The platform maps **37 Ghana NCF controls** across 6 domains to **93 ISO/IEC 27002:2022 controls** across 4 themes, identifying **47 cross-framework control mappings** with varying alignment levels.

---

## 🎯 Objectives

### Primary Objective
To design and implement an automated compliance measurement system that assesses and quantifies alignment levels between Ghana's National Cybersecurity Framework and ISO/IEC 27002 for organizations operating within Ghana.

### Specific Objectives

1. **Analyze & Compare** — Review the structures of both frameworks and perform detailed control mapping to identify similarities, differences, and gaps.

2. **Develop Compliance Model** — Build a compliance measurement model and automated web-based system that evaluates and scores organizational alignment with both frameworks.

3. **Test, Validate & Report** — Generate compliance reports that provide actionable recommendations for improving cybersecurity alignment and regulatory compliance.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **📊 Interactive Dashboard** | Overview statistics, research methodology, CMM maturity model explanation, and framework summaries |
| **🔗 Control Mapping** | 47 cross-framework mappings with alignment levels (Strong/Moderate/Partial), searchable and filterable |
| **📝 Compliance Assessment** | 3-step wizard to evaluate 130 controls (37 NCF + 93 ISO) using CMM maturity sliders (Level 0-5) |
| **📈 Results & Reports** | Radar charts, bar charts, domain breakdowns, prioritized recommendations, print & JSON export |
| **🔍 Gap Analysis** | Ghana-unique controls, ISO-unique controls, structural comparison, key insights, and recommendations |
| **📱 Responsive Design** | Fully responsive across desktop, tablet, and mobile devices |
| **🎨 Modern UI** | Glassmorphism effects, animated backgrounds, scroll-reveal animations, and smooth transitions |
| **🔌 REST API** | Python backend with endpoints for frameworks, mappings, assessments, and report generation |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | HTML5, CSS3, JavaScript (Vanilla) |
| **Backend** | Python 3 (http.server, built-in libraries) |
| **Charts** | Chart.js (via CDN) |
| **Styling** | Custom CSS with CSS Grid, Flexbox, CSS Variables, and Keyframe Animations |
| **Data Storage** | localStorage (client-side), In-memory (server-side) |

> **Note:** This project intentionally uses only vanilla HTML, CSS, JavaScript, and Python — no frameworks like React, Vue, Vite, or Django.

---

## 📁 Project Structure

```
gh-cybercomply/
├── index.html          # Dashboard — Home page with stats and overview
├── mapping.html        # Control Mapping — NCF to ISO 27002 mappings
├── assessment.html     # Assessment — 3-step compliance evaluation wizard
├── results.html        # Results — Charts, scores, and recommendations
├── gaps.html           # Gap Analysis — Framework gaps and insights
├── server.py           # Python backend — REST API server
└── README.md           # Project documentation
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.6 or higher
- A modern web browser (Chrome, Firefox, Edge, Safari)

### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/gh-cybercomply.git
   cd gh-cybercomply
   ```

2. **Start the Python backend server**
   ```bash
   python server.py
   ```

3. **Open in browser**
   ```
   http://localhost:8000
   ```

> **Standalone Mode:** The frontend also works without the backend. Simply open `index.html` directly in a browser — all assessment processing runs locally via JavaScript and localStorage.

---

## 📖 Usage

### 1. Dashboard
- View key statistics (37 NCF controls, 93 ISO controls, 47 mappings)
- Understand the research objectives and scoring methodology
- Review the CMM maturity levels (0-5)

### 2. Control Mapping
- Browse all 47 cross-framework control mappings
- Filter by alignment level: **Strong**, **Moderate**, or **Partial**
- Search for specific controls by name or ID

### 3. Compliance Assessment
- **Step 1:** Enter organization information (name, sector, size)
- **Step 2:** Rate each of the 37 Ghana NCF controls (0-5 maturity)
- **Step 3:** Rate each of the 93 ISO 27002 controls (0-5 maturity)
- Use the **Demo Fill** button to auto-populate sample data for testing

### 4. Results
- View overall compliance scores for both frameworks
- Analyze radar charts and bar chart comparisons
- Review domain-level breakdowns with progress bars
- Read prioritized recommendations (Critical/High/Medium/Low)
- **Print** the report or **Export** as JSON

### 5. Gap Analysis
- Identify 5 Ghana-unique controls not in ISO 27002
- Identify 8 ISO-unique controls not in Ghana NCF
- Compare structural differences across 8 dimensions
- Read key insights and organizational recommendations

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/frameworks/ghana` | Returns all Ghana NCF controls and domains |
| `GET` | `/api/frameworks/iso27002` | Returns all ISO/IEC 27002:2022 controls and themes |
| `GET` | `/api/mapping` | Returns cross-framework control mappings |
| `GET` | `/api/gaps` | Returns gap analysis data |
| `POST` | `/api/assess` | Submit assessment scores and receive compliance results |
| `POST` | `/api/report` | Generate a detailed compliance report |

### Example — Submit Assessment
```bash
curl -X POST http://localhost:8000/api/assess \
  -H "Content-Type: application/json" \
  -d '{
    "organization": "Acme Corp",
    "sector": "Financial Services",
    "ghana_scores": {"GH-GOV-001": 4, "GH-GOV-002": 3},
    "iso_scores": {"ISO-5.1": 4, "ISO-5.2": 3}
  }'
```

---

## 🧮 Scoring Methodology

### Capability Maturity Model (CMM) Levels

| Level | Name | Description |
|-------|------|-------------|
| 0 | Non-existent | No controls or processes in place |
| 1 | Initial | Ad-hoc, unstructured processes |
| 2 | Developing | Basic processes defined but inconsistent |
| 3 | Defined | Standardized and documented processes |
| 4 | Managed | Measured, monitored, and controlled |
| 5 | Optimized | Continuous improvement and optimization |

### Compliance Score Formula

```
Score = (Σ (control_score × weight) / Σ (max_score × weight)) × 100
```

Where:
- `control_score` = Maturity level assigned (0-5)
- `weight` = Control importance weight (default: 1.0)
- `max_score` = Maximum possible score (5)

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## 👤 Author

**John Doe**

- GitHub: [@00johndoe](https://github.com/00johndoe)

---
Developed as part of a research study on comparative evaluation of cybersecurity frameworks for organizations in Ghana.

---

## 🙏 Acknowledgments

- **National Cyber Security Authority (NCSA), Ghana** — For the National Cybersecurity Framework
- **International Organization for Standardization (ISO)** — For ISO/IEC 27002:2022
- **Chart.js** — For interactive chart visualizations

---

> **GH-CYBERCOMPLY** — Bridging the Gap Between National Policy and International Standards
