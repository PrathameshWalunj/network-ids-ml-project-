import pandas as pd
import os
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def preprocess_data(data):
    # Handle missing values
    data = data.replace([np.inf, -np.inf], np.nan).dropna()
    
    # Convert categorical variables to numerical
    le = LabelEncoder()
    label_column = ' Label' if ' Label' in data.columns else 'Label'
    data[label_column] = le.fit_transform(data[label_column])
    
    # Separate features and target
    columns_to_drop = [col for col in [' Label', 'Label', ' Flow ID', ' Source IP', ' Destination IP', ' Timestamp'] if col in data.columns]
    X = data.drop(columns_to_drop, axis=1, errors='ignore')
    y = data[label_column]
    
    # Normalize numerical features
    scaler = StandardScaler()
    X = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)
    
    return X, y

def train_and_evaluate_knn(X_train, X_test, y_train, y_test, n_neighbors=5):
    # Train a KNN classifier
    knn = KNeighborsClassifier(n_neighbors=n_neighbors)
    knn.fit(X_train, y_train)
    
    # Make predictions
    y_pred = knn.predict(X_test)
    
    # Print classification report
    print(classification_report(y_test, y_pred))
    
    # Plot and save confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(10,8))
    sns.heatmap(cm, annot=True, fmt='d')
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.savefig(f'confusion_matrix_{n_neighbors}.png')
    plt.close()
    
    return knn

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
            data = pd.read_csv(file_path, encoding='utf-8', low_memory=False)
            print("Data shape:", data.shape)
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
            
            # Preprocess data
            X, y = preprocess_data(data)
            
            # Split the data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Train and evaluate KNN model
            knn_model = train_and_evaluate_knn(X_train, X_test, y_train, y_test)
            
            print("\nKNN Model trained and evaluated.")
            print("\n" + "="*50 + "\n")
        
        except Exception as e:
            print(f"Error processing {file}: {str(e)}")
            continue

print("Exploring MachineLearningCVE data:")
explore_csv_files(os.path.join(data_dir, 'MachineLearningCVE'))

print("Exploring TrafficLabelling data:")
explore_csv_files(os.path.join(data_dir, 'TrafficLabelling'))

print("PCAP files in data directory:")
pcap_files = [f for f in os.listdir(data_dir) if f.endswith('.pcap')]
for pcap in pcap_files:
    print(pcap)
