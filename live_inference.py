import pandas as pd
import os
import defense
from plyer import notification

# Constants for thresholds
IP_SPOOF_THRESHOLD = 500        # If more than 500 unique IPs appear in 5 seconds
SINGLE_IP_SYN_THRESHOLD = 100   # If one IP sends more than 100 SYNs
SSH_BRUTE_FORCE_PACKETS = 50    # High packet count to port 22
WEB_ATTACK_MAX_BYTES = 500      # Small payload constraint for Port 80 exploits

def evaluate_traffic(traffic_features):
    """Analyzes traffic for multiple attack vectors and updates the dashboard."""
    
    unique_ip_count = len(traffic_features)
    alert_triggered = False
    alert_msg = ""
    anomalies = pd.DataFrame()

    # 1. Check for Distributed/Spoofed Attack (DDoS)
    if unique_ip_count > IP_SPOOF_THRESHOLD:
        alert_triggered = True
        alert_msg = f"DDoS/Spoofing Detected: {unique_ip_count} unique IPs active!"
        anomalies = traffic_features 
    
    # 2. Check for Specific Target Attacks (Single or multiple IPs)
    else:
        # Initialize masks (filters) for different attack types
        mask_syn = traffic_features['syn_count'] > SINGLE_IP_SYN_THRESHOLD
        
        # Only check port-based rules if 'dst_port' was extracted by Scapy
        if 'dst_port' in traffic_features.columns:
            mask_ssh = (traffic_features['dst_port'] == 22) & (traffic_features['packet_count'] > SSH_BRUTE_FORCE_PACKETS)
            mask_web = (traffic_features['dst_port'] == 80) & (traffic_features['total_bytes'] < WEB_ATTACK_MAX_BYTES)
            mask_botnet = (traffic_features['dst_port'] == 4444)
        else:
            # Fallback if ports aren't available yet
            mask_ssh = mask_web = mask_botnet = pd.Series(False, index=traffic_features.index)

        # Combine all masks: if ANY of these are true, flag as anomaly
        combined_mask = mask_syn | mask_ssh | mask_web | mask_botnet
        anomalies = traffic_features[combined_mask]

        if not anomalies.empty:
            alert_triggered = True
            if mask_syn.any():
                alert_msg = f"SYN Flood DoS detected from {mask_syn.sum()} source(s)."
            elif mask_botnet.any():
                alert_msg = "Potential Botnet C2 Communication Detected!"
            elif mask_ssh.any():
                alert_msg = f"SSH Brute Force Attempt from {mask_ssh.sum()} source(s)."
            elif mask_web.any():
                alert_msg = "Possible Web Exploit/Scan Detected!"

    if alert_triggered:
        # Save to CSV so the Tkinter Dashboard updates
        anomalies.to_csv('outputs/alerts.csv', index=False)
        
        # Windows Desktop Notification
        notification.notify(
            title='XAI-IDS SECURITY ALERT',
            message=alert_msg,
            app_name='XAI-IDS',
            timeout=5
        )
        print(f"[ALERT] {alert_msg}")
        
        # COMBAT STEP: a system-level response
        if unique_ip_count > IP_SPOOF_THRESHOLD or SINGLE_IP_SYN_THRESHOLD:
            print("RECOMMENDATION: Enable Windows SYN Attack Protection (Registry modification required).")
            print("WARNING: Too many spoofed IPs. Skipping individual firewall blocks to protect Host OS.")
        else:
            # Automatically block the specific attacking IPs
            unique_attackers = anomalies['src_ip'].unique()
            for ip in unique_attackers:
                defense.block_ip(ip)
    else:
        # Clear alerts if traffic returns to normal
        if os.path.exists('outputs/alerts.csv'):
            os.remove('outputs/alerts.csv')