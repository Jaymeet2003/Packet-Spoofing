from scapy.all import IP, UDP, send
import sys

def send_packet(src_ip, dst_ip, dst_port, payload):
    
    try:
        # Check if the payload is within the 150 bytes size limit
        if len(payload) > 150:
            raise ValueError("Payload exceeds 150 bytes. Exiting.")
        
        # create a spoofed ip_packet with source and destination
        ip_packet = IP(src = src_ip,dst = dst_ip)
        
        # create a spoofed udp port to connect
        udp_segment = UDP(dport = dst_port)
        
        # concate the final_packet with the headers, that is ip_packet, udp_segment and payload
        final_packet = ip_packet/udp_segment/payload
        
        # send the final_packet
        send(final_packet)
        print("Packet sent successfully.")
    except Exception as e:
        print(f"An error occured {e}")
        
        
if __name__ == "__main__":   
    if len(sys.argv) != 5:
        print("Usage: spoofer.py src_ip dst_ip dst_port payload")
    else:
        src_ip = sys.argv[1]
        dst_ip = sys.argv[2]
        dst_port = int(sys.argv[3])
        payload = sys.argv[4]
        send_packet(src_ip, dst_ip, dst_port, payload)
    
