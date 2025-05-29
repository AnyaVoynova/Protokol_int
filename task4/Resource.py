import time
from threading import Thread
from dns_server import save, load

from dnslib import DNSRecord, QTYPE


class Resource:
    def __init__(self, name):
        self.name = name
        self.NSA = None
        self.NS = None
        self.A = None
        self.AAAA = None
        self.PTR = None
        self.off = False

    def __hash__(self):
        return hash(self.name)

    def add_resource(self, data: DNSRecord):
        # Add the resource to the cache based on the query type
        if data.q.qtype == QTYPE.A:
            self.A = list(map(lambda x: x.rdata, data.rr))
            self.NSA = list(map(lambda x: (x.rname, x.rdata), data.ar))
            self.NS = list(map(lambda x: x.rdata, data.auth))
        elif data.q.qtype == QTYPE.AAAA:
            self.AAAA = list(map(lambda x: x.rdata, data.rr))
            self.NSA = list(map(lambda x: (x.rname, x.rdata), data.ar))
            self.NS = list(map(lambda x: x.rdata, data.auth))
        elif data.q.qtype == QTYPE.PTR:
            self.PTR = data.auth[0].rdata
        elif data.q.qtype == QTYPE.NS:
            self.NS = list(map(lambda x: x.rdata, data.rr))
            self.NSA = list(map(lambda x: (x.rname, x.rdata), data.ar))
        else:
            pass

        # Start a thread to delete the resource from the cache after TTL
        Thread(target=Resource.delete_resource, args=(self, data.q.qtype, 20)).start()

    @staticmethod
    def delete_resource(resource, qtype: QTYPE, ttl):
        time.sleep(ttl)
        qtypes = {
            QTYPE.A: [resource.A, resource.NSA, resource.NS],
            QTYPE.AAAA: [resource.AAAA, resource.NSA, resource.NS],
            QTYPE.PTR: [resource.PTR],
            QTYPE.NS: [resource.NS, resource.NSA]
        }
        # Set the resource attributes to None after TTL to remove them from the cache
        for item in qtypes[qtype]:
            item = None

        print(f'Removed from cache: {resource.name}  {qtype}')
        save()
        print(f"Saved current cache")
        load()