import streamlit as st
import pickle
import pandas as pd
import numpy as np
import plotly
import plotly.graph_objs as go
import plotly.figure_factory as ff
import plotly.express as px  
from sklearn.preprocessing import OrdinalEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
import seaborn as sns

# Load the data and models
df_total = pd.read_csv("sample.csv") # , chunksize=100000
encoder = pickle.load(open("labels_encoder.pkl", "rb"))
classifier = pickle.load(open("classifier.pkl", "rb"))

# Preprocess the data

df_total = df_total[df_total['Dst Port'] != "Dst Port"]
df_total = df_total.dropna(how="any")

df_total_transformed = df_total.convert_dtypes()
df_total_transformed["Timestamp"] = pd.to_datetime(df_total_transformed["Timestamp"])
df_total_transformed_temp = df_total_transformed.set_index("Timestamp")

features = df_total_transformed.drop("Label", axis=1)
labels = df_total["Label"]
labels_encoded = encoder.transform(labels.values.reshape(-1, 1))


# Define the encoder labels
encoder_labels = {idx: ele for idx, ele in enumerate(list(encoder.categories_[0]))}


# Define the app
st.set_page_config(layout="wide")
st.title("Intrusion Detection Dashboard")


# 1. Number of different types of attacks (Bar graph)
attack_counts = df_total["Label"].value_counts()
fig_bar = go.Figure(data=[go.Bar(x=attack_counts.index, y=attack_counts.values)])
fig_bar.update_layout(title="Number of Different Types of Attacks", xaxis_title="Attack Type", yaxis_title="Count")
st.plotly_chart(fig_bar, use_container_width=True)


# 2. Benign vs. Attacks (Interactive Pie Chart)
benign_count = attack_counts["Benign"]
attack_count = attack_counts.sum() - benign_count
fig_pie = go.Figure(data=[go.Pie(labels=['Benign', 'Attack'], values=[benign_count, attack_count])])
fig_pie.update_layout(title='Benign vs. Attack Requests')
st.plotly_chart(fig_pie, use_container_width=True)


# 3. Different Labels - Benign, FTP, ... (Donut chart)
fig_donut = go.Figure(data=[go.Pie(labels=attack_counts.index, values=attack_counts.values, hole=.4)])
fig_donut.update_layout(title='Distribution of Attack Types')
st.plotly_chart(fig_donut, use_container_width=True)


# 4. Time frame with most malicious requests (Frequency) (Line Chart)
df_total_transformed = df_total.copy()
df_total_transformed["Timestamp"] = pd.to_datetime(df_total_transformed["Timestamp"])
df_total_transformed = df_total_transformed.set_index("Timestamp")
fig_line = go.Figure()
for attack_type in df_total_transformed["Label"].unique():
    attack_data = df_total_transformed.loc[df_total_transformed["Label"] == attack_type, :]
    fig_line.add_trace(go.Scatter(x=attack_data.index, y=attack_data.groupby(pd.Grouper(freq="H")).size(), mode='lines', name=attack_type))
fig_line.update_layout(title='Frequency of Attack Types Over Time', xaxis_title='Time', yaxis_title='Attack Count')
st.plotly_chart(fig_line, use_container_width=True)


# 5. Feature Importance in RandomForestClassifier
feature_importances = classifier.feature_importances_
feature_names = features.columns

# Create a horizontal bar chart with Plotly
fig = go.Figure(data=[
    go.Bar(y=feature_names, x=feature_importances, orientation='h')
])

# Set the layout of the figure
fig.update_layout(
    title="Feature Importance in Random Forest Classifier",
    xaxis_title="Feature Importance",
    yaxis_title="Feature",
    height=800,  # You can adjust the height and width as per your requirement
    width=1200
)
# Display the figure using Streamlit
st.plotly_chart(fig)


# 6. Destination Ports
fig_dst_ports = go.Figure(data=[go.Histogram(x=features["Dst Port"], nbinsx=50, histnorm='probability')])
fig_dst_ports.update_layout(title='Distribution of Destination Ports', xaxis_title='Destination Port', yaxis_title='Frequency', yaxis_type="log")
st.plotly_chart(fig_dst_ports, use_container_width=True)


# 7. Packet Distribution
fig_packet_dist = go.Figure()

fig_packet_dist.add_trace(go.Scatter(
    x=features["Fwd Pkt Len Min"],
    y=features["Active Mean"],
    mode='markers',
    marker=dict(size=10)
))

fig_packet_dist.update_layout(
    title_text="Scatter Plot of Source and Destination Bytes",
    xaxis=dict(title='Source Bytes'),
    yaxis=dict(title='Destination Bytes')
)

st.plotly_chart(fig_packet_dist)


# 8. Bwd Pkts/s Vs. Fwd Seg Size Min (Scatter plot)
fig = go.Figure(data=go.Scatter(
    x=features['Fwd Pkt Len Mean'].tolist(),
    y=features['Bwd Pkt Len Mean'].tolist(),
    mode='markers',
    marker=dict(
        color=labels_encoded,
        colorscale='Electric', #Viridis
        opacity=1.0,
        size=7
    ),
    hovertemplate='Source Bytes: %{x}<br>Destination Bytes: %{y}<br>Attack Type: %{text}',
    text=[encoder_labels[label[0]] for label in labels_encoded]
))

fig.update_layout(
    width=800,
    height=600,
    title='Scatter Plot of Source and Destination Bytes',
    xaxis_title='Source Bytes',
    yaxis_title='Destination Bytes',
    hovermode='closest'
)
st.plotly_chart(fig, use_container_width=True)

