import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import numpy as np
from scapy.all import IP, TCP, UDP
from scapy.all import PcapReader
import pandas as pd
import os
from tqdm import tqdm

feature_names_path = os.path.join(os.path.dirname(__file__), 'feature_names.joblib')
model_path = os.path.join(os.path.dirname(__file__), 'knn_model.joblib')
scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.joblib')

def load_knn_model(model_path):
    return joblib.load(model_path)

def extract_features(packet):
    features = {}
    if IP in packet:
        features[' Source IP'] = int(packet[IP].src.replace('.', ''))
        features[' Destination IP'] = int(packet[IP].dst.replace('.', ''))
        features[' Protocol'] = packet[IP].proto
        features[' Total Length of Fwd Packets'] = packet[IP].len
        features[' Fwd Packet Length Max'] = packet[IP].len
        features[' Fwd Packet Length Min'] = packet[IP].len
        features[' Fwd Packet Length Mean'] = packet[IP].len
        features[' Fwd Header Length'] = packet[IP].ihl * 4
    if TCP in packet:
        features[' Source Port'] = packet[TCP].sport
        features[' Destination Port'] = packet[TCP].dport
        features['FIN Flag Count'] = int(packet[TCP].flags & 0x01)
        features[' SYN Flag Count'] = int(packet[TCP].flags & 0x02)
        features[' RST Flag Count'] = int(packet[TCP].flags & 0x04)
        features[' PSH Flag Count'] = int(packet[TCP].flags & 0x08)
        features[' ACK Flag Count'] = int(packet[TCP].flags & 0x10)
        features[' URG Flag Count'] = int(packet[TCP].flags & 0x20)
        features['Init_Win_bytes_forward'] = packet[TCP].window
    elif UDP in packet:
        features[' Source Port'] = packet[UDP].sport
        features[' Destination Port'] = packet[UDP].dport

    # Fill in missing features with 0
    for feature in ['Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',
                    ' Total Length of Bwd Packets', ' Fwd Packet Length Std',
                    'Bwd Packet Length Max', ' Bwd Packet Length Min', ' Bwd Packet Length Mean',
                    ' Bwd Packet Length Std', 'Flow Bytes/s', ' Flow Packets/s', ' Flow IAT Mean',
                    ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min', 'Fwd IAT Total',
                    ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total',
                    ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags',
                    ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags', ' Bwd Header Length',
                    'Fwd Packets/s', ' Bwd Packets/s', ' Min Packet Length', ' Max Packet Length',
                    ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
                    ' CWE Flag Count', ' ECE Flag Count', ' Down/Up Ratio', ' Average Packet Size',
                    ' Avg Fwd Segment Size', ' Avg Bwd Segment Size', ' Fwd Header Length.1',
                    'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate',
                    ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
                    'Subflow Fwd Packets', ' Subflow Fwd Bytes', ' Subflow Bwd Packets',
                    ' Subflow Bwd Bytes', ' Init_Win_bytes_backward', ' act_data_pkt_fwd',
                    ' min_seg_size_forward', 'Active Mean', ' Active Std', ' Active Max',
                    ' Active Min', 'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min']:
        if feature not in features:
            features[feature] = 0

    return features
def process_pcap(file_path, max_packets=50000):
    print(f"Processing PCAP file: {file_path}")
    data = []
    with PcapReader(file_path) as pcap_reader:
        for i, packet in enumerate(tqdm(pcap_reader, total=max_packets)):
            if i >= max_packets:
                break
            features = extract_features(packet)
            if features:
                data.append(features)
    return pd.DataFrame(data)

def analyze_pcap(file_path, model_path, scaler_path, feature_names_path, max_packets=50000):
    df = process_pcap(file_path, max_packets)
    
    # Load the KNN model, scaler, and feature names
    knn_model = load_knn_model(model_path)
    if knn_model is None:
        return None
    try:
        scaler = joblib.load(scaler_path)
        feature_names = joblib.load(feature_names_path)
    except FileNotFoundError as e:
        print(f"File not found: {e}")
        return None

    print("Model features:", feature_names)
    print("PCAP features:", df.columns)

    # Prepare features
    features = pd.DataFrame(index=df.index, columns=feature_names)
    for col in feature_names:
        if col in df.columns:
            features[col] = df[col]
        else:
            print(f"Feature {col} not found in PCAP data, filling with 0")
            features[col] = 0  # or another appropriate default value

    # Fill NaN values
    features = features.fillna(0)

    print("Feature shape before scaling:", features.shape)
    
    # Scale the features
    try:
        scaled_features = scaler.transform(features)
    except Exception as e:
        print(f"Error during scaling: {e}")
        return None


    print("Scaled feature shape:", scaled_features.shape)
    
    # Make predictions
    try:
        predictions = knn_model.predict(scaled_features)
    except Exception as e:
        print(f"Error during prediction: {e}")
        return None
    
    df['prediction'] = predictions
    print("\nPrediction results:")
    print(df['prediction'].value_counts())
    
    # Print unique values in prediction
    print("\nUnique prediction values:")
    print(df['prediction'].unique())
    
    return df

def load_knn_model(model_path):
    try:
        return joblib.load(model_path)
    except FileNotFoundError:
        print(f"Model file not found at {model_path}")
        return None


if __name__ == "__main__":
    pcap_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'Thursday-WorkingHours.pcap')
    result = analyze_pcap(pcap_file, model_path, scaler_path, feature_names_path, max_packets=50000)
    if result is not None:
        print("\nFirst few rows of processed data with predictions:")
        print(result.head())
        print(f"\nTotal packets processed: {len(result)}")
        print("\nUnique values in 'prediction' column:")
        print(result['prediction'].unique())
        print("\nValue counts of 'prediction' column:")
        print(result['prediction'].value_counts())
    else:
        print("Analysis failed. Please check the error messages above.")
    print("Feature names from file:")
    print(joblib.load(feature_names_path))