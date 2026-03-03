#temp till the model is implemented, this file will contain the logic to evaluate the traffic features and trigger the XAI pipeline if an anomaly is detected. It will also handle saving the malicious traffic data for the Streamlit dashboard and triggering desktop notifications.
import pandas as pd
import os
from plyer import notification
from phase3_shap import generate_shap_plot

# Ensure output directory exists for Streamlit to read from
os.makedirs('outputs', exist_ok=True)

def evaluate_traffic(traffic_features):
    """Evaluates live traffic and triggers XAI pipeline if anomalous."""
    
    # PLACEHOLDER LOGIC: Simulating a model prediction. 
    # We flag an anomaly if a single IP sends >100 SYN packets or >50,000 bytes in 5 seconds.
    anomalies = traffic_features[(traffic_features['syn_count'] > 100) | 
                                 (traffic_features['total_bytes'] > 50000)]
    
    if not anomalies.empty:
        # 1. Save the malicious traffic to CSV for the Streamlit dashboard
        anomalies.to_csv('outputs/alerts.csv', index=False)
        
        # 2. Trigger Desktop Notification
        notification.notify(
            title='XAI-IDS Alert: DoS Attack!',
            message=f"Blocked malicious traffic from {len(anomalies)} IP(s). Check dashboard.",
            app_name='XAI-IDS',
            timeout=7
        )
        
        # 3. Trigger SHAP Explanation (Commented out until we train the actual DNN)
        # feature_names = ['packet_count', 'total_bytes', 'syn_count']
        # generate_shap_plot(trained_dnn_model, anomalies[feature_names], feature_names)
        
    else:
        # If traffic is normal, remove old alerts so the dashboard shows "Secure"
        if os.path.exists('outputs/alerts.csv'):
            os.remove('outputs/alerts.csv')