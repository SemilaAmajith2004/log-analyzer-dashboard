# Cybersecurity Log & Traffic Analyzer Dashboard

A lightweight, real-time web-based log analysis dashboard designed to parse web server access logs, compute traffic metrics, and automatically identify security threats such as potential brute-force attacks. Built with a Python FastAPI backend and an interactive Chart.js frontend.

---

## Key Features

* **Fast Log Parsing:** Uses Regular Expressions (Regex) and Pandas to structure unstructured HTTP access logs into clean, actionable data.
* **Automated Threat Detection:** Identifies suspicious client IP addresses based on configurable security rules (e.g., flagging IPs with three or more failed `401 Unauthorized` status codes).
* **Interactive Visual Analytics:** Displays traffic trends, status code distributions, and top requesting IP addresses using Chart.js.
* **RESTful API Architecture:** Asynchronous API endpoints developed with FastAPI, featuring automated Swagger UI documentation.

---

## System Architecture & Workflow Diagrams

### 1. High-Level System Architecture (Sequence Diagram)

Sequence.png

### 2. Backend Logic Execution Flowchart

api_log_analysis.png

---

## Tech Stack

* **Backend:** Python 3.x, FastAPI, Uvicorn, Pandas, Regex
* **Frontend:** HTML5, CSS3, JavaScript (Fetch API), Bootstrap 5, Chart.js
* **Version Control & Development:** Git, GitHub, VS Code

---

## Getting Started Locally

### 1. Prerequisites
Ensure Python 3.8+ is installed on your local environment.

### 2. Clone the Repository
```bash
git clone [https://github.com/SemilaAmajith2004/log-analyzer-dashboard.git](https://github.com/SemilaAmajith2004/log-analyzer-dashboard.git)
cd log-analyzer-dashboard