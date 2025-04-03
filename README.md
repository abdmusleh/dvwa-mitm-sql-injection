# DVWA + MITM + SQL Injection - Traffic Analysis

This project demonstrates how to perform a **Man-in-the-Middle (MITM) attack**, capture **SQL injection** traffic, and analyze it using **Scapy**. The project also integrates **SQLMap** for automated SQL injection attacks on **DVWA** (Damn Vulnerable Web Application).

## Project Overview

This project combines several concepts to simulate and analyze web security attacks:

- **MITM Attack**: Using ARP spoofing to intercept traffic between the client and the server.
- **SQL Injection**: Capturing SQL injection attempts via network traffic.
- **Traffic Analysis**: Using Scapy to analyze and categorize HTTP traffic (normal vs SQL injection).

## Project Structure

dvwa-mitm-sql-injection/ │ ├── MITM_Attack/ │ ├── mitm_arp_spoof.py # Python script for performing MITM attack │ └── capture_instructions.md # Guide for setting up MITM attack │ ├── Sniffer/ │ ├── mitm_sniffer.py # Python script for sniffing packets │ └── packet_analysis.md # Guide on analyzing captured traffic │ ├── DVWA/ │ ├── dvwa_setup.md # Instructions for setting up DVWA │ └── sqlmap_usage.md # Guide on using SQLMap for SQL injection │ ├── images/ │ ├── mitm_attack.png # Screenshot showing MITM attack in progress │ ├── sql_injection.png # Screenshot showing SQL injection traffic │ └── normal_traffic.png # Screenshot showing normal HTTP traffic │ ├── README.md # Documentation for the project └── LICENSE # Optional license file

markdown
Copy
Edit

## Setup Instructions

### 1. **Set up DVWA (Damn Vulnerable Web Application)**

Follow the instructions in `DVWA/dvwa_setup.md` to set up DVWA on your local machine. This will provide a vulnerable environment to simulate attacks.

#### Requirements:
- **Apache2** web server
- **MySQL** database
- **PHP** 7.x or higher
- **DVWA application files**

### 2. **Install Dependencies**

You need to install some dependencies for this project to work:

- **Scapy**: A Python-based network manipulation tool.
  ```bash
  pip install scapy
Wireshark: Network protocol analyzer to capture and inspect packets.

bash
Copy
Edit
sudo apt install wireshark
SQLMap: Tool for automating SQL injection attacks.

bash
Copy
Edit
sudo apt install sqlmap
3. Perform the MITM Attack
Use the script in MITM_Attack/mitm_arp_spoof.py to carry out an ARP spoofing attack. This will intercept HTTP traffic between the client and the server.

4. Capture Traffic
After performing the MITM attack, use the script in Sniffer/mitm_sniffer.py to capture and analyze the intercepted packets. The script will categorize traffic into normal and SQL injection types.

5. SQL Injection with SQLMap
Follow the guide in DVWA/sqlmap_usage.md to automate SQL injection testing using SQLMap. This tool can exploit the vulnerabilities in the DVWA environment.# dvwa-mitm-sql-injection
