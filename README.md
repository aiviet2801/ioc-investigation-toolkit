# IOC Investigation Toolkit

## Why This Project?

This project is built to learn software engineering through a real-world cybersecurity problem.

Instead of learning Python syntax in isolation, every concept is practiced while building a practical IOC investigation toolkit.

---

## Project Goal

IOC Investigation Toolkit is a personal learning project for building an OSINT investigation tool.

The objective is to investigate Indicators of Compromise (IOC) by collecting information from appropriate OSINT services and presenting the results in a consistent investigation report.

---

## Learning Objectives

This project is used to practice:

- REST API integration
- Software architecture
- Object-oriented programming
- OSINT investigation workflow
- Software design patterns
- Clean project organization
- Git workflow

---

## Current Features

### IOC Detection

- Detect IP Address
- Detect Domain
- Detect URL
- Detect MD5
- Detect SHA1
- Detect SHA256

### IP Investigation

- VirusTotal
- AbuseIPDB
- Automatic service fallback

### Domain Investigation

- VirusTotal

### URL Investigation

- VirusTotal

### General

- Validate public/private IP
- Normalize investigation data
- Basic logging
- Datetime formatting

### Report Export

- Export investigation report to HTML
- Export investigation report to PDF
---

## Current Project Structure

```text
ioc-investigation-toolkit/

├── main.py
├── README.md
├── requirements.txt
│
├── models/
│   └── report.py
│
├── services/
│   ├── virustotal.py
│   └── abuseipdb.py
│
└── utils/
    ├── logger.py
    └── ioc_detector.py
```

---

## Current Workflow

```text
                User Input
                     │
                     ▼
          IOC Type Detection
                     │
        ┌────────────┼────────────┐
        │            │            │
        ▼            ▼            ▼
        IP         DOMAIN        URL
        │            │            │
        ▼            ▼            ▼
 VirusTotal     VirusTotal   VirusTotal
        │
        ▼
 AbuseIPDB
        │
        └────────────┐
                     ▼
               Build Report
                     │
                     ▼
             Display Report
```

---

## Roadmap

### Completed

- [x] Environment setup
- [x] Git project initialization
- [x] VirusTotal IP integration
- [x] AbuseIPDB integration
- [x] Report model
- [x] Service fallback
- [x] Datetime formatting
- [x] IOC Type Detection
- [x] Domain investigation
- [x] URL investigation
- [x] Hash investigation
- [x] MD5 investigation
- [x] SHA1 investigation
- [x] SHA256 investigation
- [x] HTML report exporter
- [x] IP HTML report
- [x] Domain HTML report
- [x] URL HTML report
- [x] Hash HTML report
- [x] HTML report export
- [x] PDF report export

### Sprint 5

- [ ] Hash investigation
- [ ] SHA1 investigation
- [ ] SHA256 investigation

### Sprint 6

- [ ] HTML report
- [ ] PDF report

---

## Design Principles

- One function should have one responsibility.
- One service should communicate with one external API.
- Normalize data before presenting it.
- Prefer simple architecture.
- Build first, optimize later.
- Keep modules independent.

---

## Current Status

Version: v0.7

Current Sprint: Sprint 8

Status: In Progress