# IOC Investigation Toolkit

## Why This Project?
This project is built for learning software engineering through a real-world cybersecurity problem.

Instead of learning Python syntax in isolation, every concept is learned while building a practical IOC investigation tool.

## Project Goal
IOC Investigation Toolkit is a personal learning project for building an OSINT investigation tool.

The goal is to collect information about Indicators of Compromise (IOC) from multiple public intelligence sources and generate a unified investigation report.

## Learning Objectives
This project is used to practice:

- REST API integration
- Software architecture
- Object-oriented programming
- OSINT investigation workflow
- Clean project organization

## Current Features
- Lookup IP address using VirusTotal
- Lookup IP address using AbuseIPDB
- Validate public/private IP
- Merge multiple OSINT sources into one report
- Service fallback
- Basic logging

## Current Project Structure
ioc-investigation-toolkit/

├── main.py

├── models/

├── services/

├── utils/

└── README.md

## Current Workflow
```text
User Input
    │
    ▼
Validate IOC
    │
    ▼
VirusTotal
    │
    ▼
AbuseIPDB
    │
    ▼
Build Report
    │
    ▼
Display Report
```

## Roadmap

### Completed
- [x] Environment setup
- [x] VirusTotal integration
- [x] AbuseIPDB integration
- [x] Report model
- [x] Service fallback
- [x] Datetime formatting

### Sprint 3

- [ ] IOC Type Detection

## Design Principles
- Keep one function responsible for one task.
- Keep external services isolated.
- Normalize data before presenting it.
- Build first, optimize later.
- Keep the project simple.

## Current Status
Version: v0.2

Current Sprint: Sprint 3

Status: In Progress