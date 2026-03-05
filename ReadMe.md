# Password Spray Attack Detection

## Project Overview

This project detects Password Spray Attacks by analyzing login attempt logs using Python.
A password spray attack occurs when an attacker tries the same password across multiple user accounts to avoid account lockouts.

The system simulates login attempts, analyzes authentication logs, and detects suspicious patterns where a single password is used across many users.

---

## Features

- Simulates login attempts (normal and malicious)
- Generates authentication log files
- Detects password spray attack patterns
- Generates summary reports of login attempts

---

## Project Structure
```text

Password_Spray_project/
│
├── attack_simulation.py     # Generates login logs
├── detection_engine.py      # Detects password spray attacks
├── reporting.py             # Displays attack alerts and summary
├── login_logs.csv           # Log file containing login attempts
└── README.md                # Project documentation

```
---

## Technologies Used

- Python
- CSV log analysis
- Basic data structures for pattern detection

---

## How the Project Works

1. Attack Simulation

"attack_simulation.py" generates login attempts and stores them in a log file.

Log fields:

- Timestamp
- Username
- Password used
- Login status (SUCCESS / FAIL)

---

2. Detection Engine

"detection_engine.py" analyzes the log file and detects suspicious patterns.

Detection rule:

- If the same password is attempted on multiple users, it may indicate a password spray attack.

---

3. Reporting Module

"reporting.py" generates:

- Attack alerts
- Summary of login attempts
- Number of failed attempts per user

---

## Requirements

- Python 3.7 or higher

(Optional)

pip install matplotlib

---

## How to Run the Project

Step 1: Generate Logs

python attack_simulation.py

Step 2: Detect Attack

python detection_engine.py

Step 3: Generate Report

python reporting.py

---

## Learning Objectives

- Understand password spray attacks
- Learn log analysis for security monitoring
- Implement simple cybersecurity detection techniques using Python