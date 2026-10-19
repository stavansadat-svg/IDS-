# AI-Based Intrusion Detection System for IoT Devices (MQTT-Based)

A hybrid machine learning intrusion detection system for a simulated MQTT IoT device,
built by modifying and extending a published research implementation with a self-captured
dataset, an added anomaly-detection layer, and a full real-time pipeline.

## Overview

This project simulates an IoT sensor communicating over MQTT, attacks it using common
network-based attack techniques, and detects those attacks in real time using a hybrid
of supervised (Random Forest) and unsupervised (Isolation Forest) machine learning models.

- **Simulated IoT device:** a Python/paho-mqtt script publishing fake sensor readings
- **Attack lab:** Kali Linux running Nmap scans, Hydra SSH brute-force, and MQTT flooding
  against the simulated device
- **Detection pipeline:** flow-based feature extraction → Random Forest + Isolation Forest
  → Flask API → live traffic agent → Streamlit dashboard

## Based On

This project extends the implementation from:

> Hindy, H., Bayne, E., Bures, M., Atkinson, R., Tachtatzis, C., & Bellekens, X. (2020).
> *Machine Learning Based IoT Intrusion Detection System: An MQTT Case Study
> (MQTT-IoT-IDS2020 Dataset).*
> Code: https://github.com/AbertayMachineLearningGroup/MQTT_ML

Modifications made in this project:
- Fixed deprecated scikit-learn code so the pipeline runs on a modern install
- Replaced the static published dataset with traffic captured from a self-built attack lab
- Added an Isolation Forest model for detecting attacks outside the known training classes
- Built a complete real-time inference pipeline (Flask API, live agent, Streamlit dashboard),
  which the original implementation does not include

ids_project/
├── data/
│ ├── raw_pcaps/ # Captured network traffic (not included — see .gitignore)
│ └── dataset.csv # Extracted flow-based features (benign/scan/bruteforce/mqtt_flood)
├── models/ # Trained model files 
├── extract_features.py # Converts .pcap captures into labeled flow-based features
├── train_models.py # Trains Random Forest + Isolation Forest
├── app.py # Flask API (POST /predict)
├── live_agent.py # Live traffic capture + automatic classification
├── dashboard.py # Streamlit live monitoring dashboard
└── README.md

## Requirements

- Two VMs (or equivalent): an attacker machine (Kali Linux) and a target machine (Ubuntu)
  on a shared private network
- Python 3, with: `paho-mqtt`, `scapy`, `pandas`, `scikit-learn`, `flask`, `requests`, `streamlit`
- Mosquitto MQTT broker installed on the target machine

## Setup & Usage

```bash
# 1. Install dependencies
python3 -m venv hids-env
source hids-env/bin/activate
pip install paho-mqtt scapy pandas scikit-learn flask requests streamlit

# 2. Start the simulated IoT sensor
python3 iot_sensor.py

# 3. Capture traffic and build the dataset (see extract_features.py for pcap paths)
python3 extract_features.py

# 4. Train the models
python3 train_models.py

# 5. Start the detection API
python3 app.py

# 6. Start the live agent (requires root for packet capture)
sudo ./hids-env/bin/python3 live_agent.py

# 7. Launch the dashboard
streamlit run dashboard.py
```

Open `http://localhost:8501` to view the live dashboard.

## Attack Scenarios Tested

| Attack | Tool | Label |
|---|---|---|
| Port/service scan | `nmap -sV` | `scan` |
| SSH brute-force | `hydra` | `bruteforce` |
| MQTT publish flood | `mosquitto_pub` | `mqtt_flood` |
| Legitimate traffic | `mosquitto_sub` / sensor | `benign` |

## Results

Random Forest achieves a weighted average near 1.00 across all four classes on
self-captured lab data, consistent with the base paper's reported 99.97% accuracy on
flow-based features. Isolation Forest, trained only on benign traffic, correctly flags
over 99% of attack traffic as anomalous, providing a safeguard against attack types
outside the labeled training set.

## Limitations & Future Work

- Lab-based (VirtualBox), not tested on physical hardware or production-scale traffic
- Isolation Forest not yet tested against a genuinely unseen attack type
- No automated response (e.g., IP blocking) implemented yet

## License / Academic Note

This is an academic project submitted as part of a university coursework assignment.
Base implementation adapted from the Hindy et al. (2020) MQTT_ML repository (see citation above).
