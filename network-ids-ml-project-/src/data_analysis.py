import pandas as pd
import os

# Get the path to the data directory
data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')

def explore_csv_files(directory):
    if not os.path.exists(directory):
        print(f"Directory not found: {directory}")
        return

    csv_files = [f for f in os.listdir(directory) if f.endswith('.csv')]
    
    if not csv_files:
        print(f"No CSV files found in {directory}")
        return

    for file in csv_files:
        print(f"\nExploring file: {file}")
        file_path = os.path.join(directory, file)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = pd.read_csv(f)
                print("Data shape:", data.shape)
                print("\nColumn names:")
                print(data.columns.tolist())
                
                if 'Label' in data.columns:
                    print("\nClass distribution:")
                    print(data['Label'].value_counts())
                elif ' Label' in data.columns:  # Note the space before Label
                    print("\nClass distribution:")
                    print(data[' Label'].value_counts())
                else:
                    print("\nNo 'Label' column found in this file.")
                
                print("\nFirst few rows:")
                print(data.head())
                
                print("\n" + "="*50 + "\n")
        
        except Exception as e:
            print(f"Error reading {file}: {str(e)}")
            continue

print("Exploring MachineLearningCVE data:")
explore_csv_files(os.path.join(data_dir, 'MachineLearningCVE'))

print("Exploring TrafficLabelling data:")
explore_csv_files(os.path.join(data_dir, 'TrafficLabelling'))

print("PCAP files in data directory:")
pcap_files = [f for f in os.listdir(data_dir) if f.endswith('.pcap')]
for pcap in pcap_files:
    print(pcap)
