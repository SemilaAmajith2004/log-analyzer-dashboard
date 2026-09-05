# Cybersecurity Log & Traffic Analyzer Dashboard

A lightweight, real-time web-based log analysis dashboard designed to parse web server access logs, compute traffic metrics, and automatically identify security threats such as potential brute-force attacks. Built with a Python FastAPI backend and an interactive Chart.js frontend.

---

## Key Features

* **Fast Log Parsing:** Uses Regular Expressions (Regex) and Pandas to structure unstructured HTTP access logs into clean, actionable data.
* **Automated Threat Detection:** Identifies suspicious client IP addresses based on configurable security rules (e.g., flagging IPs with three or more failed `401 Unauthorized` status codes).
* **Interactive Visual Analytics:** Displays traffic trends, status code distributions, and top requesting IP addresses using Chart.js.
* **RESTful API Architecture:** Asynchronous API endpoints developed with FastAPI, featuring automated Swagger UI documentation.

---

## System Architecture & Flowchart

### 1. High-Level Data Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Administrator
    participant Frontend as Web Dashboard (HTML/JS)
    participant FastAPI as FastAPI Backend
    participant Parser as Parsing & Analysis Engine

    User->>Frontend: Select & Upload 'sample_access.log'
    Frontend->>FastAPI: POST /api/analyze (Multipart File)
    FastAPI->>Parser: Read & Parse Log Lines via Regex
    Parser->>Parser: Calculate Top IPs & Status Codes
    Parser->>Parser: Detect Brute Force Patterns (401 >= 3)
    Parser-->>FastAPI: Return Aggregated JSON Data
    FastAPI-->>Frontend: HTTP 200 OK (JSON Response)
    Frontend->>User: Render Visual Charts & Security Alerts