# Packet Spoofing

## Overview
This repository contains the files and answers for Homework 2 of the CS 494: Network Security course. Below is the description of each file included in the submission.

## Files Included
1. **hw2.txt** - Contains the answers to all text-based questions, formatted according to the assignment's instructions.
2. **6.jpg** - The extracted JPEG image from the Wireshark trace as required by question 6.
3. **10.pcap** - Packet capture file generated by capturing live HTTP and DNS traffic while making a request to `example.com` as specified in question 10.
4. **spoofer.py** - Python script implementing the packet spoofing task using the `scapy` module. The script meets the required specifications, including creating a spoofed UDP packet and handling payload limitations.

## How to Run
1. **Wireshark Analysis**: Load `trace1.pcap` or `trace2.pcap` in Wireshark to view packet details as referenced in the `hw2.txt` answers.
2. **Spoofer Script**: To run the packet spoofing script, execute the `spoofer.py` file with the appropriate arguments:
   ```bash
   python3 spoofer.py <src_ip> <dst_ip> <dst_port> <payload>
