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
from malware_analysis import analyze_file
import random
import time


# Paths
data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
model_path = os.path.join(os.path.dirname(__file__), 'knn_model.joblib')
scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.joblib')

def load_quotes(file_name= 'quotes.txt'):
    file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), file_name)
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]
    
quotes = load_quotes()

if 'quote_index' not in st.session_state:
    st.session_state.quote_index = 0
    st.session_state.last_update = time.time()



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

    return pd.concat(all_data, ignore_index=True)




#Main app

current_time = time.time()
if current_time - st.session_state.last_update > 10:
    st.session_state.quote_index = (st.session_state.quote_index + 1) % len(quotes)
    st.session_state.last_update = current_time

quote = quotes[st.session_state.quote_index]
st.markdown(f"<p style='font-size: 14px; font-style: italic; text-align: center;'>{quote}</p>", unsafe_allow_html=True)


st.title('Network Intrusion Detection and Malware Analysis System')       



# Tabs
tab1, tab2 = st.tabs(["Network IDS", "Malware Analysis"])

with tab1:
    
    st.header('Network Intrusion Detection System')
    
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

        for i, (count, percentage) in enumerate(zip(attack_counts, attack_percentages)):
            ax.text(i, count, f'{percentage:.1f}%', ha='center', va='bottom')

        plt.tight_layout()
        st.pyplot(fig)

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
                    0: "BENIGN", 1: "FTP-Patator", 2: "SSH-Patator", 3: "DoS slowloris",
                    4: "DoS Slowhttptest", 5: "DoS Hulk", 6: "DoS GoldenEye", 7: "Heartbleed",
                    8: "Web Attack – Brute Force", 9: "Web Attack – XSS", 10: "Web Attack – Sql Injection",
                    11: "Infiltration", 12: "Bot", 13: "PortScan", 14: "DDoS"
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
    st.write("Acceptable file formats: .exe, .dll, .sys, .pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx, .zip, .rar, .7z, .tar, .gz, .js, .vbs, .ps1, .bat, .cmd, .hta, .jar, .py, .php, .asp, .aspx, .jsp, .htm, .html")
    
    uploaded_file = st.file_uploader("Choose a file for malware analysis", type=None)
    similarity_threshold = st.slider("Select similarity threshold for code comparison", 0, 100, 50)
    
    if st.button('Perform Static Analysis'):
        if uploaded_file is not None:
            with open("temp_file", "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            analysis_result = analyze_file("temp_file", similarity_threshold)
            
            st.subheader("Basic File Information")
            st.write(f"File Name: {analysis_result['file_name']}")
            st.write(f"File Size: {analysis_result['file_size']} bytes")
            st.write(f"File Type: {analysis_result['file_type']}")
            st.write(f"MD5 Hash: {analysis_result['md5']}")
            st.write(f"SHA256 Hash: {analysis_result['sha256']}")
            st.write(f"Entropy: {analysis_result['entropy']:.2f}")

            with st.expander("Extracted Strings"):
                st.write(analysis_result['strings'])

            st.subheader("Analysis Results")
            
            if analysis_result['entropy'] > 7.2:
                with st.expander("Malware Likelihood"):
                    likelihood = analysis_result.get('malware_likelihood', 0)
                    st.write(f"Malware Likelihood: {likelihood}%")
                    st.write("Note: This likelihood is based on file entropy > 7.2 and the presence of certain strings.")
                    st.write("Category: High Risk" if likelihood >= 50 else "Category: Medium Risk")
            
            if 'virustotal' in analysis_result:
                with st.expander("VirusTotal Analysis"):
                    vt_result = analysis_result['virustotal']
                    if 'positives' in vt_result:
                        st.write(f"Detection ratio: {vt_result['positives']}/{vt_result['total']}")
                        st.write(f"Scan date: {vt_result['scan_date']}")
                        if 'popular_threat_classification' in vt_result:
                            st.write("Popular Threat Classification:")
                            for category in vt_result['popular_threat_classification'].get('suggested_threat_label', []):
                                st.write(f"- {category}")
                        if 'names' in vt_result:
                            st.write("Common names:")
                            for name in vt_result['names'][:5]:
                                st.write(f"- {name}")
                    elif 'error' in vt_result:
                        st.write(f"VirusTotal API error: {vt_result['error']}")
            
            if 'mitre_attack' in analysis_result:
                with st.expander("MITRE ATT&CK Techniques"):
                    mitre_data = analysis_result['mitre_attack']
                    if isinstance(mitre_data, list):
                        for technique in mitre_data:
                            if isinstance(technique, dict):
                                st.markdown(f"**{technique.get('technique', 'Unknown')}** ({technique.get('id', 'Unknown')})")
                                st.write(technique.get('description', 'No description available'))
                                st.write("---")
                    elif isinstance(mitre_data, dict):
                        for key, value in mitre_data.items():
                            st.markdown(f"**{key}**")
                            st.write(value)
                            st.write("---")
                    else:
                        st.write(str(mitre_data))
            
            if 'yara_matches' in analysis_result:
                with st.expander("Yara Rule Matches"):
                    for rule in analysis_result['yara_matches']:
                        st.write(f"- {rule}")
            
            if 'code_similarities' in analysis_result:
                with st.expander(f"Code Similarity to Known Malware (Threshold: {similarity_threshold}%)"):
                    similarities = [s for s in analysis_result['code_similarities'] if s[1] >= similarity_threshold]
                    if similarities:
                        for known_hash, similarity in similarities:
                            st.write(f"- {similarity}% similar to {known_hash}")
                    else:
                        st.write("No significant code similarities found above the threshold.")
            
            if 'pe_info' in analysis_result:
                with st.expander("PE File Information"):
                    st.json(analysis_result['pe_info'])
                if 'suspicious_imports' in analysis_result['pe_info']:
                    with st.expander("Suspicious Imports"):
                        for imp in analysis_result['pe_info']['suspicious_imports']:
                            st.write(f"- {imp}")
            
            st.write("For a more comprehensive analysis, consider using professional antivirus software or submitting the file to online malware analysis services.")
            
            os.remove("temp_file")
        else:
            st.error("Please upload a file before performing the analysis.")

