## Real-Time DDoS Intrusion Detection System (NIDS)

A high-performance Network Intrusion Detection System (NIDS) that utilizes Unsupervised Machine Learning (Isolation Forest) to detect zero-day DDoS attacks in real-time. The system features a Hybrid Threat Classifier to identify specific attack types (UDP/SYN/FIN Floods) and a modern React Dashboard for live monitoring.

Key Features

Real-Time Packet Sniffing: Captures live network traffic using Scapy without external tools.

Unsupervised AI Detection: Uses Isolation Forest to detect anomalies and zero-day attacks without needing labeled attack datasets.

Hybrid Threat Classification: Combines ML scores with heuristic rule-based logic to classify attacks as UDP Flood, SYN Flood, or Normal Traffic.

Live Dashboard: A responsive React UI that visualizes the Safety Score, Live Packet Matrix, and Traffic Volume with <1s latency.

Automated Email Alerts: Triggers SMTP email notifications to administrators when the Safety Score drops below critical thresholds.

Forensic Reporting: Exports a full session CSV report containing all captured flows and their anomaly scores for post-attack analysis.

Tech Stack

Backend (Python)

FastAPI: High-performance REST API for asynchronous processing.

Scapy: For raw packet capture and feature extraction.

Scikit-learn: Implementation of the Isolation Forest algorithm.

Pandas/NumPy: Data preprocessing and real-time statistical analysis.

Frontend (React)

Vite: Blazing fast build tool.

Recharts: For real-time telemetry graphs.

Lucide React: For modern UI iconography.

Tailwind CSS: For the "Dark Mode" aesthetic and responsive design.

Usage Guide

Start the System: Open the dashboard (usually running on localhost:5173).

Activate Sensor: Click the "START LIVE SENSOR" button. The system will begin intercepting packets from your network interface.

Monitor Status: Watch the Safety Score gauge.

Green (>80): Safe / Normal Traffic.

Red (<50): Critical / Attack Detected.

View Matrix: Switch to the "Flow Matrix" tab to see individual packet IPs and their classification (e.g., "UDP Flood Attack").

Generate Report: Click "STOP & GENERATE REPORT" to end the session. Then click "Full Dataset Report" to download the CSV logs.

Project Structure

DDOS-IDS-SCANNER/
├── api.py                 # Main Backend Entry Point (FastAPI + Sniffer)
├── iso_forest_model.pkl   # Pre-trained ML Model
├── nids-sentinel/         # Frontend React App
│   ├── src/
│   │   ├── App.jsx        # Main Dashboard UI Logic
│   │   ├── main.jsx       # React Entry Point
│   └── package.json       # JS Dependencies
└── README.md              # Documentation



Contribution

Contributions are welcome! Please fork this repository and submit a pull request for any feature enhancements or bug fixes.

Fork the Project

Create your Feature Branch

Commit your Changes

Push to the Branch

Open a Pull Request

Developed by ALWYN SHARON A & YOGESWARAN CS | Cybersecurity Project

