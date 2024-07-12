import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
import joblib

from scapy.all import PcapReader
import pandas as pd
import os
from tqdm import tqdm

model_path = os.path.join(os.path.dirname(__file__), 'knn_model.joblib')
scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.joblib')

def load_knn_model(model_path):
    return joblib.load(model_path)

def extract_features(packet):
    features = {}
    if 'IP' in packet:
        features['ip_len'] = packet['IP'].len
        features['ip_proto'] = packet['IP'].proto
    if 'TCP' in packet:
        features['tcp_sport'] = packet['TCP'].sport
        features['tcp_dport'] = packet['TCP'].dport
        features['tcp_flags'] = int(packet['TCP'].flags)
    if 'UDP' in packet:
        features['udp_sport'] = packet['UDP'].sport
        features['udp_dport'] = packet['UDP'].dport
        features['udp_len'] = packet['UDP'].len
    return features

def process_pcap(file_path, max_packets=1000):
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

def analyze_pcap(file_path, model_path, scaler_path, max_packets=1000):
    df = process_pcap(file_path, max_packets)
    
    # Load the KNN model and scaler
    knn_model = load_knn_model(model_path)
    if knn_model is None:
        return None
    try:
        scaler = joblib.load(scaler_path)
    except FileNotFoundError:
        print(f"Scaler file not found at {scaler_path}")
        return None
    expected_features = ['ip_len', 'ip_proto', 'tcp_sport', 'tcp_dport', 'tcp_flags', 'udp_sport', 'udp_dport', 'udp_len']
    missing_features = [feat for feat in expected_features if feat not in df.columns]
    if missing_features:
        print(f"Warning: Missing features in PCAP data: {missing_features}")
        # Add missing features with default value 0
        for feat in missing_features:
            df[feat] = 0    
    
    # Prepare the features
    features = df[expected_features]
    features = features.fillna(0) # Replace NaN with 0
    
    # Scale the features
    scaled_features = scaler.transform(features)
    
    # Make predictions
    predictions = knn_model.predict(scaled_features)
    df['prediction'] = predictions
    
    print("\nPrediction results:")
    print(df['prediction'].value_counts())
    
    return df

def load_knn_model(model_path):
    try:
        return joblib.load(model_path)
    except FileNotFoundError:
        print(f"Model file not found at {model_path}")
        return None


if __name__ == "__main__":
    pcap_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'Thursday-WorkingHours.pcap')
    result = analyze_pcap(pcap_file, model_path, scaler_path)
    if result is not None:
        print("\nFirst few rows of processed data with predictions:")
        print(result.head())
        print(f"\nTotal packets processed: {len(result)}")
    else:
        print("Analysis failed. Please check the error messages above.")