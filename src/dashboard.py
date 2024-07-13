import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os
import ipaddress
from malware_analysis import analyze_file  # Import the analyze_file function

# Paths
data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
model_path = os.path.join(os.path.dirname(__file__), 'knn_model.joblib')
scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.joblib')

@st.cache_data
def load_and_preprocess_data():
    all_data = []
    for file in os.listdir(os.path.join(data_dir, 'MachineLearningCVE')):
        if file.endswith('.csv'):
            file_path = os.path.join(data_dir, 'MachineLearningCVE', file)
            df = pd.read_csv(file_path, encoding='utf-8', low_memory=False)
            all_data.append(df)
    
    if not all_data:
        st.error("No data could be loaded from the CSV files.")
        return None

    data = pd.concat(all_data, ignore_index=True)
    return data

# Streamlit app
st.title('Network Intrusion Detection and Malware Analysis System')

# Create tabs for Network IDS and Malware Analysis
tab1, tab2 = st.tabs(["Network IDS", "Malware Analysis"])

with tab1:
    st.header('Network Intrusion Detection System')
    
    # Load data
    data = load_and_preprocess_data()

    if data is not None:
        st.subheader('Data Overview')
        st.write(data.head())

        st.subheader('Basic Statistics')
        st.write(data.describe())

        st.subheader('Attack Distribution')
        fig, ax = plt.subplots(figsize=(12, 6))
        attack_counts = data[' Label'].value_counts()
        total = len(data)
        attack_percentages = (attack_counts / total) * 100

        bars = attack_counts.plot(kind='bar', ax=ax)
        ax.set_ylabel('Count (log scale)')
        ax.set_yscale('log')
        ax.set_title('Distribution of Network Traffic Types')
        plt.xticks(rotation=45, ha='right')

        # Add percentage labels on top of each bar
        for i, (count, percentage) in enumerate(zip(attack_counts, attack_percentages)):
            ax.text(i, count, f'{percentage:.1f}%', ha='center', va='bottom')

        plt.tight_layout()
        st.pyplot(fig)

        # Display actual counts and percentages
        st.write("Actual counts and percentages:")
        st.write(pd.DataFrame({'Count': attack_counts, 'Percentage': attack_percentages.round(2)}))

        if os.path.exists(model_path) and os.path.exists(scaler_path):
            model = joblib.load(model_path)
            scaler = joblib.load(scaler_path)
            feature_names = joblib.load(os.path.join(os.path.dirname(__file__), 'feature_names.joblib'))

            st.subheader('Real-time Prediction')
            st.write("Enter values for the features used in the model.")

            user_input = {}
            cols = st.columns(2)
            for i, feature in enumerate(feature_names):
                with cols[i % 2]:
                    user_input[feature] = st.number_input(f"{feature}", value=0.0, help=f"Enter the value for {feature}")

            if st.button('Predict'):
                input_df = pd.DataFrame([user_input])
                scaled_input = scaler.transform(input_df)
                prediction = model.predict(scaled_input)
                st.write(f"Predicted class: {prediction[0]}")

                label_meanings = {
                    0: "BENIGN",
                    1: "FTP-Patator",
                    2: "SSH-Patator",
                    3: "DoS slowloris",
                    4: "DoS Slowhttptest",
                    5: "DoS Hulk",
                    6: "DoS GoldenEye",
                    7: "Heartbleed",
                    8: "Web Attack – Brute Force",
                    9: "Web Attack – XSS",
                    10: "Web Attack – Sql Injection",
                    11: "Infiltration",
                    12: "Bot",
                    13: "PortScan",
                    14: "DDoS"
                }
                
                predicted_label = label_meanings.get(prediction[0], "Unknown Attack Type")
                st.write(f"Interpretation: {predicted_label}")

        else:
            st.warning("Model or scaler not found. Prediction feature unavailable.")

    else:
        st.error("No data available for Network IDS. Please check your data directory and file permissions.")

with tab2:
    st.header('Malware Analysis')
    st.write("Upload a file for static malware analysis.")
    st.write("Acceptable file formats : .exe, .dll, .sys, .pdf, .doc, .xls, .xlsx, .ppt, .pptx, .zip, .tar, .gz, .js, .vbs, .ps1, .bat, .cmd, .hta, .jar, .py, .php, .asp, .aspx, .jsp, .htm, .html ")
    uploaded_file = st.file_uploader("Choose a file for malware analysis", type=None)
    
    if st.button('Perform Static Analysis'):
        if uploaded_file is not None:
            # Save the uploaded file temporarily
            with open("temp_file", "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            # Analyze the file
            analysis_result = analyze_file("temp_file")
            
            # Display the results
            st.write("File Analysis Results:")
            st.json(analysis_result)
            

            # Explain malware likelihood
            st.subheader("Malware Likelihood Interpretation")
            likelihood = analysis_result.get('malware_likelihood', 0)
            st.write(f"Malware Likelihood: {likelihood}%")
            st.write("Note: This likelihood is based on a simple heuristic analysis and should not be considered definitive.")
            st.write("The likelihood is calculated based on file entropy and the presence of certain strings.")
            if likelihood < 50:
                st.write("Category: Low Risk")
            elif 50 <= likelihood < 75:
                st.write("Category: Medium Risk")
            else:
                st.write("Category: High Risk")
            st.write("For a more comprehensive analysis, consider using professional antivirus software or submitting the file to online malware analysis services.")
            
            
            # Remove the temporary file
            os.remove("temp_file")
        else:
            st.error("Please upload a file before performing the analysis.")