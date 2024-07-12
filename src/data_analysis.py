import pandas as pd
import os
import ipaddress
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from tqdm import tqdm
import joblib



model_path = os.path.join(os.path.dirname(__file__), 'knn_model.joblib')
scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.joblib')

def preprocess_data(data):
    print("Preprocessing data...")
    # Handle missing values
    data = data.replace([np.inf, -np.inf], np.nan).dropna()

    # Convert IP addresses to numerical values
    if ' Source IP' in data.columns:
        data[' Source IP'] = data[' Source IP'].apply(lambda x: int(ipaddress.ip_address(x)))
    if ' Destination IP' in data.columns:
        data[' Destination IP'] = data[' Destination IP'].apply(lambda x: int(ipaddress.ip_address(x)))

    # Handle 'Flow ID' column
    if 'Flow ID' in data.columns:
        data = data.drop('Flow ID', axis=1)

    # Convert categorical variables to numerical
    le = LabelEncoder()
    label_column = ' Label' if ' Label' in data.columns else 'Label'
    data[label_column] = le.fit_transform(data[label_column])

    # Convert all columns to numeric, dropping any that can't be converted
    for col in data.columns:
        if col != label_column:
            try:
                data[col] = pd.to_numeric(data[col], errors='raise')
            except ValueError:
                print(f"Dropping column {col} as it cannot be converted to numeric")
                data = data.drop(col, axis=1)

    # Separate features and target
    y = data[label_column]
    X = data.drop([label_column], axis=1)

    
    print("Preprocessing completed.")

    # Normalize numerical features
    scaler = StandardScaler()
    X = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)

    return X, y, scaler

def train_and_evaluate_knn(X_train, X_test, y_train, y_test, scaler, n_neighbors=5):
    print(f"Training KNN model with {n_neighbors} neighbors...")
    knn = KNeighborsClassifier(n_neighbors=n_neighbors)
    knn.fit(X_train, y_train)
    
    print("Making predictions...")
    y_pred = knn.predict(X_test)
    
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    
    print("Generating confusion matrix...")
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(10,8))
    sns.heatmap(cm, annot=True, fmt='d')
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.savefig(f'confusion_matrix_{n_neighbors}.png')
    plt.close()
    
    print(f"Confusion matrix saved as confusion_matrix_{n_neighbors}.png")
    print(f"Saving model to {model_path}")
    joblib.dump(knn, model_path)
    print(f"Saving scaler to {scaler_path}")
    joblib.dump(scaler, scaler_path)

    return knn


data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')

def explore_csv_files(directory, max_rows=None):
    print(f"Exploring directory: {directory}")
    if not os.path.exists(directory):
        print(f"Directory not found: {directory}")
        return

    csv_files = [f for f in os.listdir(directory) if f.endswith('.csv')]
    if not csv_files:
        print(f"No CSV files found in {directory}")
        return

    print(f"Found {len(csv_files)} CSV files. Processing...")

    for file in csv_files:
        print(f"\nExploring file: {file}")
        file_path = os.path.join(directory, file)
        
        try:
            print(f"Reading CSV file (up to {max_rows} rows)...")
            data = pd.read_csv(file_path, encoding='utf-8', low_memory=False, nrows=max_rows)
            print(f"CSV file read successfully. Shape: {data.shape}")
            
            print("\nColumn names:")
            print(data.columns.tolist())
            
            label_column = ' Label' if ' Label' in data.columns else 'Label'
            if label_column in data.columns:
                print("\nClass distribution:")
                print(data[label_column].value_counts())
            else:
                print("\nNo 'Label' column found in this file.")
            
            print("\nFirst few rows:")
            print(data.head())
            
            X, y, scaler = preprocess_data(data)
            
            print("Splitting data...")
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            print("Data split completed.")
            
            knn_model = train_and_evaluate_knn(X_train, X_test, y_train, y_test, scaler)
            print("\nKNN Model trained and evaluated.")
            
            print("\n" + "="*50 + "\n")
        
        except Exception as e:
            print(f"Error processing {file}: {str(e)}")
            continue

    print(f"Finished processing all files in {directory}")

if __name__ == "__main__":
    print("Exploring MachineLearningCVE data:")
    explore_csv_files(os.path.join(data_dir, 'MachineLearningCVE'), max_rows=100000)
    
    print("\nExploring TrafficLabelling data:")
    explore_csv_files(os.path.join(data_dir, 'TrafficLabelling'), max_rows=100000)
    
    print("\nPCAP files in data directory:")
    pcap_files = [f for f in os.listdir(data_dir) if f.endswith('.pcap')]
    for pcap in pcap_files:
        print(pcap)