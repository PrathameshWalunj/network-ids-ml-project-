import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import PcapReader
import pandas as pd
import os
from tqdm import tqdm

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

def analyze_pcap(file_path, max_packets=1000):
    df = process_pcap(file_path, max_packets)
    print("\nBasic statistics of extracted features:")
    print(df.describe())
    return df

if __name__ == "__main__":
    pcap_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'Thursday-WorkingHours.pcap')
    result = analyze_pcap(pcap_file, max_packets=1000)
    print("\nFirst few rows of processed data:")
    print(result.head())
    print(f"\nTotal packets processed: {len(result)}")