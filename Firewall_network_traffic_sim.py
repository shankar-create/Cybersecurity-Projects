import random

# Define the packets
class Packet:
    def __init__(self, sent_ip, des_ip, sent_port, des_port, protocol):
        self.sent_ip = sent_ip
        self.des_ip = des_ip
        self.sent_port = sent_port
        self.des_port = des_port
        self.protocol = protocol

    def __repr__(self):
        return f"Packet({self.sent_ip}, {self.des_ip}, {self.sent_port}, {self.des_port}, {self.protocol})"

# Define the firewall rule
class FirewallRule:
    def __init__(self, action, sent_ip=None, des_ip=None, sent_port=None, des_port=None, protocol=None):
        self.action = action
        self.sent_ip = sent_ip
        self.des_ip = des_ip
        self.sent_port = sent_port
        self.des_port = des_port
        self.protocol = protocol

    def match(self, packet):
        if self.sent_ip and self.sent_ip != packet.sent_ip:
            return False
        if self.des_ip and self.des_ip != packet.des_ip:
            return False
        if self.sent_port and self.sent_port != packet.sent_port:
            return False
        if self.des_port and self.des_port != packet.des_port:
            return False
        if self.protocol and self.protocol != packet.protocol:
            return False
        return True  # Packet matches the rule

    def __repr__(self):
        return f"FirewallRule({self.action}, {self.sent_ip}, {self.des_ip}, {self.sent_port}, {self.des_port}, {self.protocol})"

# Firewall processing
class Firewall:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule):
        self.rules.append(rule)

    def process_packet(self, packet):
        for rule in self.rules:
            if rule.match(packet):
                print(f"Packet {packet} matches rule {rule} → Action: {rule.action}")
                return rule.action
        print(f"Packet {packet} does not match any rule → Action: block")
        return "block"

# Function to generate random packets
def gen_random_packets():
    protocols = ["TCP", "UDP", "HTTP"]
    sent_ip = f"192.168.1.{random.randint(1, 255)}"
    des_ip = f"192.168.1.{random.randint(1, 255)}"
    sent_port = random.randint(1024, 65535)
    des_port = random.randint(1024, 65535)
    protocol = random.choice(protocols)
    return Packet(sent_ip, des_ip, sent_port, des_port, protocol)

# Example of usage
def simulate_firewall():
    # Create a firewall
    firewall = Firewall()
    
    rule_nos = int(input("How many rules do you want to add?: "))
    
    for i in range(rule_nos):
        sent_ip = input("Enter the IP address to block : ").strip() or None
        des_ip = input("Enter the destination IP to block : ").strip() or None
        sent_port = input("Enter the source port to block : ").strip()
        des_port = input("Enter the destination port to block : ").strip()
        protocol = input("Enter the protocol to block : ").strip() or None

        sent_port = int(sent_port) if sent_port else None
        des_port = int(des_port) if des_port else None
        
        firewall.add_rule(FirewallRule(action="block", sent_ip=sent_ip, des_ip=des_ip, sent_port=sent_port, des_port=des_port, protocol=protocol))

    # Simulate network traffic
    print("\nSimulating network traffic...\n")
    
    for _ in range(5):
        packet = gen_random_packets()
        firewall.process_packet(packet)
        print("-" * 50)

# Run the simulation
simulate_firewall()
