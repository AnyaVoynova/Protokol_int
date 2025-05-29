from socket import *
from dnslib import *

SERVER_PORT = 53
SERVER_HOST = '127.0.0.1'

# Create a UDP socket
with socket.socket(socket.AF_INET, SOCK_DGRAM) as sock:
    # Connect to the DNS server
    sock.connect((SERVER_HOST, SERVER_PORT))

    # Get user input for domain name and query type
    user_input = input("Enter domain name and query type (A, AAAA, NS, PTR): ")

    # Continue until user enters 'q' to quit
    while user_input != 'q':
        # Split the user input into a list
        input_list = user_input.split(' ')
        dns_request = 0

        # Check if the user provided both domain name and query type
        if len(input_list) > 1:
            # Create a DNS request based on the query type
            if input_list[1] == "A":
                dns_request = DNSRecord(q=DNSQuestion(input_list[0], QTYPE.A))
            elif input_list[1] == "AAAA":
                dns_request = DNSRecord(q=DNSQuestion(input_list[0], QTYPE.AAAA))
            elif input_list[1] == "NS":
                dns_request = DNSRecord(q=DNSQuestion(input_list[0], QTYPE.NS))
            elif input_list[1] == "PTR":
                dns_request = DNSRecord(q=DNSQuestion(input_list[0], QTYPE.PTR))
            else:
                print("Invalid query type")
                user_input = input("Enter domain name and query type (A, AAAA, NS, PTR): ")
                continue
        # If only domain name is provided, default to A query type
        elif len(input_list) == 1:
            dns_request = DNSRecord(q=DNSQuestion(input_list[0], QTYPE.A))
        else:
            print("Invalid query type")
            user_input = input("Enter domain name and query type (A, AAAA, NS, PTR): ")
            continue

        # Send the DNS request to the server
        sock.send(dns_request.pack())

        # Receive the response from the server
        response, server_address = sock.recvfrom(1024)

        # Parse and print the DNS response
        print(DNSRecord.parse(response))

        # Get the next user input
        user_input = input("Enter domain name and query type (A, AAAA, NS, PTR): ")

    # Close the socket
    sock.close()