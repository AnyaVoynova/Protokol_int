from threading import Thread
import pickle

import Resource

from dnslib import *

DNS_PORT = 53
DNS_HOST = '127.0.0.1'
HOST_DNS = '8.26.56.26'
cache = {}  # Dictionary to store cached resources
alive = True  # Flag to control server status (on/off)
flag = False  # Flag to check if a request has been received
default_ttl = 30  # Default time-to-live value for cached resources


def save():
    # Save the cache dictionary to a pickle file
    with open("cache.pickle", "wb") as write_file:
        pickle.dump(cache, write_file)


def load():
    # Load the cache dictionary from the pickle file
    global cache, default_ttl
    with open("cache.pickle", "rb") as read_file:
        cache = pickle.load(read_file)


def send_dns_request(dns_server, p):
    try:
        dns_server.send(p)
        p2, a2 = dns_server.recvfrom(1024)
        print('Sent DNS request to the server')
        return p2
    except:
        print('DNS server is not responding')
        return


def start_server():
    global cache, alive, flag, default_ttl
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_server:
            server.bind((DNS_HOST, DNS_PORT))
            server.settimeout(30)
            dns_server.connect((HOST_DNS, DNS_PORT))
            dns_server.settimeout(30)
            print('Server started')
            while True:
                while alive:
                    try:
                        client_req, client_addr = server.recvfrom(1024)
                        client_data = DNSRecord.parse(client_req)
                        print(f'Received request: {client_data.q.qname}  {client_data.q.qtype}')
                    except:
                        print('No requests received in the last 30 seconds')
                        continue
                    flag = True
                    if str(client_data.q.qname) in cache:
                        resource: Resource = cache.get(str(client_data.q.qname))
                        query = client_data.reply()
                        if client_data.q.qtype == QTYPE.A and resource.A:
                            # Process A record query from cache
                            flag = False
                            for addr in resource.A:
                                query.add_answer(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.A,
                                           ttl=default_ttl,
                                           rdata=A(addr.data)))
                            for ns in resource.NS:
                                query.add_auth(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.NS,
                                           ttl=default_ttl,
                                           rdata=NS(ns.label)))
                            for ns, nsA in resource.NSA:
                                if len(nsA.data) == 4:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.A,
                                                        ttl=default_ttl,
                                                        rdata=A(nsA.data)))
                                elif len(nsA.data) == 16:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.AAAA,
                                                        ttl=default_ttl,
                                                        rdata=AAAA(nsA.data)))

                        elif client_data.q.qtype == QTYPE.AAAA and resource.AAAA:
                            # Process AAAA record query from cache
                            flag = False
                            for addr in resource.AAAA:
                                query.add_answer(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.AAAA,
                                           ttl=default_ttl,
                                           rdata=AAAA(addr.data)))
                            for ns in resource.NS:
                                query.add_auth(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.NS,
                                           ttl=default_ttl,
                                           rdata=NS(ns.label)))
                            for ns, nsA in resource.NSA:
                                if len(nsA.data) == 4:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.A,
                                                        ttl=default_ttl,
                                                        rdata=A(nsA.data)))
                                elif len(nsA.data) == 16:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.AAAA,
                                                        ttl=default_ttl,
                                                        rdata=AAAA(nsA.data)))

                        elif client_data.q.qtype == QTYPE.PTR and resource.PTR:
                            # Process PTR record query from cache
                            flag = False
                            query.add_auth(dns.RR(rname=client_data.q.qname,
                                                  rclass=client_data.q.qclass,
                                                  rtype=QTYPE.SOA,
                                                  ttl=default_ttl,
                                                  rdata=resource.PTR))
                        elif client_data.q.qtype == QTYPE.NS and resource.NS:
                            # Process NS record query from cache
                            flag = False
                            for ns in resource.NS:
                                query.add_answer(
                                    dns.RR(rname=client_data.q.qname,
                                           rclass=client_data.q.qclass,
                                           rtype=QTYPE.NS,
                                           ttl=default_ttl,
                                           rdata=NS(ns.label)))
                            for ns, nsA in resource.NSA:
                                if len(nsA.data) == 4:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.A,
                                                        ttl=default_ttl,
                                                        rdata=A(nsA.data)))
                                elif len(nsA.data) == 16:
                                    query.add_ar(dns.RR(rname=ns.label,
                                                        rclass=client_data.q.qclass,
                                                        rtype=QTYPE.AAAA,
                                                        ttl=default_ttl,
                                                        rdata=AAAA(nsA.data)))

                        else:
                            # Forward the request to the DNS server and cache the response
                            server_packet = send_dns_request(dns_server, client_req)
                            server_data: DNSRecord = DNSRecord.parse(server_packet)
                            cache.get(str(client_data.q.qname)).add_resource(server_data)
                            print("Cached the response")
                            server.sendto(server_packet, client_addr)
                            print('Sent the response')
                            continue
                    if not cache.get(str(client_data.q.qname)):
                        # Request not in cache, forward to DNS server and cache the response
                        server_packet = send_dns_request(dns_server, client_req)
                        cache[str(client_data.q.qname)] = Resource.Resource(
                            str(client_data.q.qname))
                        server_data = DNSRecord.parse(server_packet)
                        cache[str(client_data.q.qname)].add_resource(server_data)
                        print(f'Cached: {client_data.q.qname} {client_data.q.qtype}')
                        server.sendto(server_packet, client_addr)
                        print('Sent the response')
                    else:
                        # Serve the response from cache
                        server.sendto(query.pack(), client_addr)
                        print(f"Sent the cached packet: "
                              f"{client_data.q.qname}  {client_data.q.qtype}")
                save()
                cache = {}
                print('Saved the cache')
                print('Server turned off')
                while not alive:
                    time.sleep(5)
                print('Server started')
                load()
                print('Loaded the save')


def main():
    global alive
    Thread(target=start_server).start()
    while True:
        alive = True
        while input() != 'q':
            continue
        alive = False
        while input() != 's':
            continue


if __name__ == '__main__':
    main()