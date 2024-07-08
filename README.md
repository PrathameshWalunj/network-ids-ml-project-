# Network Intrusion Detection System using Machine Learning

An intelligent system designed to detect and classify network attacks using machine learning techniques, focusing on the K-Nearest Neighbors algorithm and the CICIDS2017 dataset.

![Python](https://img.shields.io/badge/python-v3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
## Project Overview
This project implements a Network Intrusion Detection System (IDS) using machine learning techniques, specifically the K-Nearest Neighbors (KNN) algorithm. The goal is to detect various types of network attacks by analyzing network traffic patterns from the CICIDS2017 dataset.

## Features
- Data analysis and preprocessing of the CICIDS2017 dataset
- Implementation of KNN classifier for multi-class attack detection
- Basic packet inspection capabilities using Scapy
- Visualization of network traffic patterns and attack distributions

## Installation
To set up this project, follow these steps:

1. Clone the repository:
   git clone https://github.com/PrathameshWalunj/network-ids-ml-project.git
   cd network-ids-ml-project
2. Install the required packages:
   pip install -r requirements.txt
## Dataset
This project uses the CICIDS2017 dataset, which includes:
- Benign network traffic
- Various attack types: DoS, DDoS, Brute Force, XSS, SQL Injection, Infiltration, Port Scan

To use the dataset:
1. Download it from: https://www.unb.ca/cic/datasets/ids-2017.html
2. Place the CSV files in the `data/` directory

## Usage
1. Data Analysis and Model Training:

python src/data_analysis.py
This script:
- Loads and preprocesses the CICIDS2017 dataset
- Performs exploratory data analysis
- Trains a KNN model for attack classification
- Outputs performance metrics and visualizations

2. Packet Inspection (for future implementation):
python src/packet_analysis.py
This script will provide basic packet inspection capabilities using Scapy.

## Project Structure
- `data/`: Directory for storing the CICIDS2017 dataset (not tracked by git)
- `src/`: Source code for the project
- `data_analysis.py`: Main script for data processing and model training
- `packet_analysis.py`: Script for basic packet inspection (to be implemented)
- `notebooks/`: Jupyter notebooks for exploratory data analysis (to be added)
- `requirements.txt`: List of required Python packages
- `.gitignore`: Specifies intentionally untracked files to ignore

## Current Status
- Initial project setup completed
- Basic data loading and preprocessing implemented
- KNN model implementation in progress
- Packet inspection capabilities to be developed

## Next Steps
1. Complete KNN model implementation and evaluation
2. Implement basic packet inspection using Scapy
3. Create visualizations for network traffic patterns
4. Explore additional machine learning models for comparison
5. Develop real-time analysis capabilities

## Acknowledgments
- Canadian Institute for Cybersecurity for providing the CICIDS2017 dataset
- Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani for their work in creating and documenting the CICIDS2017 dataset


## License
MIT License

Project Link: https://github.com/PrathameshWalunj/network-ids-ml-project
