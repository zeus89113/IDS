from scapy.all import get_if_list, show_interfaces

# This shows the "friendly name" and the "Scapy name"
show_interfaces()

print("\n--- List of all Interface Names ---")
print(get_if_list())