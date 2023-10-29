import time
import hashlib
import random

# Vulnerability Class: Represents a security vulnerability with attributes such as likelihood and impact.
class Vulnerability:
    def __init__(self, name, likelihood, impact):
        self.name = name
        self.likelihood = likelihood
        self.impact = impact
        self.risk = likelihood * impact

# Attack Class: Represents an attack that consists of multiple vulnerabilities.
class Attack:
    def __init__(self, name, vulnerabilities):
        self.name = name
        self.vulnerabilities = vulnerabilities

# Function to evaluate the total risk associated with the attack.
    def evaluate_risk(self):
        total_risk = sum(v.risk for v in self.vulnerabilities)
        return total_risk

# Mitigation Class: Represents a mitigation strategy that can be applied to an attack.
class Mitigation:
    def __init__(self, name, effectiveness):
        self.name = name
        self.effectiveness = effectiveness

# Function to apply the mitigation to an attack and reduce the risks of involved vulnerabilities.
    def apply(self, attack):
        print(f"\nSIMULATION for {attack.name}\n\nApplying Mitigation: {self.name} to Attack: {attack.name}")
        for vulnerability in attack.vulnerabilities:
            original_risk = vulnerability.risk
            likelihood_score = vulnerability.likelihood
            vulnerability.risk *= (1 - self.effectiveness)
            print(f" - Vulnerability: {vulnerability.name}, Likelihood: {likelihood_score},Original Risk: {original_risk}, Mitigated Risk: {vulnerability.risk}")

# SmartDevice Class: Represents a smart device in the home environment.
class SmartDevice:
    def __init__(self, device_id, controller):
        self.device_id = device_id
        self.controller = controller
        self.is_authenticated = False

# Function to authenticate the device using a secret key.
    def authenticate(self, secret_key):
        hashed_key = hashlib.sha256(secret_key.encode()).hexdigest()
        if hashed_key == "expected_hashed_key":
            self.is_authenticated = True
            print(f"Device {self.device_id} authenticated.")

# Function for the device to send status messages to the controller.
    def send_status(self, status):
        if self.is_authenticated:
            encrypted_status = hashlib.md5(status.encode()).hexdigest()
            success = random.random() > 0.1  # 10% chance of message loss
            if success:
                time.sleep(random.uniform(0, 2))  # Simulate latency
                self.controller.receive_status(self.device_id, encrypted_status)
            else:
                print(f"Device {self.device_id} status message lost.")

# Function for the device to receive commands from the controller.
    def receive_command(self, encrypted_command):
        if self.is_authenticated:
            decrypted_command = encrypted_command  # Add decryption logic here
            print(f"Device {self.device_id} received command: {decrypted_command}")

# Controller Class: Represents the controller coordinating the smart devices.
class Controller:
    def __init__(self):
        self.devices = {}

# Function to register devices to the controller.
    def register_device(self, device, secret_key):
        self.devices[device.device_id] = device
        device.authenticate(secret_key)

# Function for the controller to receive status messages from devices.
    def receive_status(self, device_id, encrypted_status):
        decrypted_status = encrypted_status  # Add decryption logic here
        print(f"Controller received status from Device {device_id}: {decrypted_status}")

# Function for the controller to send commands to devices.
    def send_command(self, device_id, command):
        device = self.devices.get(device_id)
        if device:
            encrypted_command = hashlib.md5(command.encode()).hexdigest()
            device.receive_command(encrypted_command)

# Simulate the operation
controller = Controller()
device1 = SmartDevice(device_id=1, controller=controller)
controller.register_device(device1, secret_key="shared_secret")

device1.send_status("ON")
controller.send_command(device_id=1, command="TURN_OFF")

# Define vulnerabilities or how the attack can be executed for Unauthorized Access
v1 = Vulnerability(name="Brute Force", likelihood=0.25, impact=0.8)
v2 = Vulnerability(name="Credential Theft", likelihood=0.75, impact=0.9)


# Define vulnerabilities or how the attack can be executed for Malware Injection
v3 = Vulnerability(name="Phishing Attack", likelihood=0.5, impact=0.8)
v4 = Vulnerability(name="Drive By Downloads", likelihood=0.5, impact=0.9)


# Define attacks
attack1 = Attack(name="Unauthorized Access", vulnerabilities=[v1, v2])
attack2 = Attack(name="Malware Injection", vulnerabilities=[v3, v4])


# Define mitigations
mitigation1 = Mitigation(name="Strong Password Policy", effectiveness=0.8)
mitigation2 = Mitigation(name="Using an Intrusion Detection System", effectiveness=0.9)

# Applying mitigations and printing output
mitigation1.apply(attack1)
mitigation2.apply(attack2)

# Calculating and printing the remaining risk after all mitigations have been applied.
remaining_risk1 = attack1.evaluate_risk()
print(f"\nRemaining risk after applying mitigations for Unauthorized Access: {remaining_risk1}")

remaining_risk2 = attack2.evaluate_risk()
print(f"\nRemaining risk after applying mitigations for Malware Injection: {remaining_risk2}\n")