import subprocess

def block_ip(attacker_ip):
    """Adds a Windows Firewall rule to block an IP."""
    rule_name = f"XAI_IDS_BLOCK_{attacker_ip}"
    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={attacker_ip}'
    
    try:
        # Check if rule already exists to avoid duplicates
        check_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        
        if "No rules match" in result.stdout:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL)
            print(f"[DEFENSE] Successfully blocked IP: {attacker_ip}")
    except Exception as e:
        print(f"[DEFENSE] Failed to block {attacker_ip}: {e}")

def unblock_all():
    """Removes all firewall rules created by the IDS."""
    command = 'netsh advfirewall firewall delete rule name=all | findstr XAI_IDS_BLOCK'
    subprocess.run(command, shell=True)
    print("[DEFENSE] All blocked IPs have been cleared.")