# Network Intrusion Detection System using Machine Learning & Malware Analysis System

An intelligent system designed to detect and classify network attacks using machine learning techniques, focusing on the K-Nearest Neighbors algorithm and the CICIDS2017 dataset along with static malware analysis features.

![Python](https://img.shields.io/badge/python-v3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-v1.22.0-brightgreen.svg)
![Altair](https://img.shields.io/badge/Altair-v4.2.0-red.svg)
![Pandas](https://img.shields.io/badge/Pandas-v1.5.3-yellow.svg)
![Numpy](https://img.shields.io/badge/Numpy-v1.24.3-lightgrey.svg)
![Matplotlib](https://img.shields.io/badge/Matplotlib-v3.7.1-orange.svg)
![Seaborn](https://img.shields.io/badge/Seaborn-v0.12.2-blue.svg)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-v1.2.2-yellowgreen.svg)
![Scapy](https://img.shields.io/badge/Scapy-v2.5.0-blueviolet.svg)
![Joblib](https://img.shields.io/badge/Joblib-v1.2.0-blue.svg)
![Tqdm](https://img.shields.io/badge/Tqdm-v4.65.0-orange.svg)
![Pefile](https://img.shields.io/badge/Pefile-2023.2.7-informational.svg)
![Python-Magic](https://img.shields.io/badge/Python--Magic-v0.4.27-ff69b4.svg)
![Requests](https://img.shields.io/badge/Requests-v2.31.0-critical.svg)
![Python-Dotenv](https://img.shields.io/badge/Python--Dotenv-v1.0.0-9cf.svg)
![Ipaddress](https://img.shields.io/badge/Ipaddress-v1.0.23-important.svg)
![Yara-Python](https://img.shields.io/badge/Yara--Python-v4.3.1-lightgrey.svg)
![Ssdeep](https://img.shields.io/badge/Ssdeep-v3.4-success.svg)

## Project Overview
This project implements a comprehensive Network Intrusion Detection System (IDS) with integrated malware analysis capabilities. It uses machine learning techniques, specifically the K-Nearest Neighbors (KNN) algorithm, to detect various types of network attacks by analyzing network traffic patterns from the CICIDS2017 dataset. Additionally, it includes static malware analysis features to provide a more robust security analysis tool.

## Features

   ## Network Intrusion Detection
- Data analysis and preprocessing of the CICIDS2017 dataset
- Implementation of KNN classifier for multi-class attack detection
- Basic packet inspection capabilities using Scapy
- Visualization of network traffic patterns and attack distributions
  ## Malware Analysis
- File information extraction (hash, size, type, strings)
- Entropy calculation
- VirusTotal lookup for threat intelligence
- MITRE ATT&CK technique identification
- YARA rule matching for known malware patterns
- Code similarity comparison with known malware samples
- Fuzzing capabilities to identify potential vulnerabilities
- Suspicious import detection for PE files
  ## Dockerized Application for Easy Deployment
- Containerized application for simplified deployment
- Easy setup and teardown using Docker commands
- Environment consistency across different development and production systems
  
  



## Installation
To set up this project, follow these steps:

1. Clone the repository:
   git clone https://github.com/PrathameshWalunj/network-ids-ml-project.git
   cd network-ids-ml-project
2. Install the required packages:
   pip install -r requirements.txt
3. Build the Docker image:
   docker build -t nids-malware-analysis:latest .
4. Run the Docker container:
   docker run -d -p 8501:8501 -v "${PWD}/data:/app/data" --name nids-app nids-malware-analysis:latest
## Dataset
This project uses the CICIDS2017 dataset, which includes:
- Benign network traffic
- Various attack types: DoS, DDoS, Brute Force, XSS, SQL Injection, Infiltration, Port Scan

To use the dataset:
1. Download it from: https://www.unb.ca/cic/datasets/ids-2017.html
2. Place the CSV files in the `data/` directory

## Project Structure
- data/: Directory for storing the CICIDS2017 dataset and PCAP files
- src/: Source code for the project

- dashboard.py: Main Streamlit application
- data_analysis.py: Script for data processing and model training
- packet_analysis.py: Script for packet inspection using Scapy
- malware_analysis.py: Module for static malware analysis


- Dockerfile: Instructions for building the Docker image
- requirements.txt: List of required Python packages
- .gitignore: Specifies intentionally untracked files to ignore
## Current Status
- Initial project setup completed
- Basic data loading and preprocessing implemented
- KNN model implementation in progress
- Packet inspection capabilities to be developed

## Known Issues
- Docker containerization is currently experiencing issues. The application may not run consistently within the Docker container due to resource constraints and potential conflicts.
- The application runs perfectly fine when executed directly with streamlit run dashboard.py in a properly set up Python environment.
- Large data files may cause Docker build issues due to space constraints.

## Running without Docker
- If you encounter issues with Docker, you can run the application directly:

- Ensure you have Python 3.9+ installed
- Install the required packages: pip install -r requirements.txt
- Run the application: streamlit run src/dashboard.py

## Future Improvements
1. Optimize Docker image size and build process
2. Expand the range of detectable attack types
3. Improve machine learning model performance
4. Enhance malware analysis capabilities
5. Implement comprehensive error handling and logging

## Acknowledgments
- Canadian Institute for Cybersecurity for providing the CICIDS2017 dataset
- Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani for their work in creating and documenting the CICIDS2017 dataset
- The open-source community for various libraries and tools used in this project


## License
This project is licensed under the MIT License - see the LICENSE file for details
## Contact
- pwalu1@unh.newhaven.edu
- Project Link: https://github.com/PrathameshWalunj/network-ids-ml-project

