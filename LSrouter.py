####################################################
# LSrouter.py
# Name:
# HUID:
#####################################################

from router import Router
from packet import Packet
import json
import heapq

class LSrouter(Router):
    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time
        self.last_time = 0

        self.sequence_number = 0
        self.topology = {}  # {router_addr: {neighbor_addr: cost}}
        self.forwarding_table = {}  # {destination: next_hop}
        self.ports = {}  # {neighbor_addr: port}
        self.link_state_db = {}  # {router_addr: (seq_num, {neighbor: cost})}

    def handle_packet(self, port, packet):
        if packet.is_traceroute:
            dst = packet.dst_addr
            if dst in self.forwarding_table:
                next_hop = self.forwarding_table[dst]
                if next_hop in self.ports:
                    self.send(self.ports[next_hop], packet)
        else:
            content = json.loads(packet.content)
            origin = content["origin"]
            seq = content["seq"]
            links = content["links"]

            if origin not in self.link_state_db or seq > self.link_state_db[origin][0]:
                self.link_state_db[origin] = (seq, links)
                self._recompute_forwarding_table()
                self._flood(packet, exclude_port=port)

    def handle_new_link(self, port, endpoint, cost):
        self.ports[endpoint] = port
        if self.addr not in self.topology:
            self.topology[self.addr] = {}
        self.topology[self.addr][endpoint] = cost

        self.sequence_number += 1
        self.link_state_db[self.addr] = (self.sequence_number, self.topology[self.addr])
        self._recompute_forwarding_table()
        self._broadcast_link_state()

    def handle_remove_link(self, port):
        remove_endpoint = None
        for neighbor, p in self.ports.items():
            if p == port:
                remove_endpoint = neighbor
                break
        if remove_endpoint:
            del self.ports[remove_endpoint]
            if self.addr in self.topology and remove_endpoint in self.topology[self.addr]:
                del self.topology[self.addr][remove_endpoint]

        self.sequence_number += 1
        self.link_state_db[self.addr] = (self.sequence_number, self.topology.get(self.addr, {}))
        self._recompute_forwarding_table()
        self._broadcast_link_state()

    def handle_time(self, time_ms):
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_link_state()

    def _broadcast_link_state(self):
        packet = Packet(
            kind=Packet.ROUTING,
            src_addr=self.addr,
            dst_addr=None,
            content=json.dumps({
                "origin": self.addr,
                "seq": self.sequence_number,
                "links": self.topology.get(self.addr, {})
            })
        )
        for neighbor, port in self.ports.items():
            self.send(port, packet)

    def _flood(self, packet, exclude_port=None):
        for neighbor, port in self.ports.items():
            if port != exclude_port:
                self.send(port, packet)

    def _recompute_forwarding_table(self):
        graph = {}
        for router, (_, neighbors) in self.link_state_db.items():
            graph[router] = neighbors

        dist = {self.addr: 0}
        prev = {}
        heap = [(0, self.addr)]

        while heap:
            d, u = heapq.heappop(heap)
            for v in graph.get(u, {}):
                alt = d + graph[u][v]
                if v not in dist or alt < dist[v]:
                    dist[v] = alt
                    prev[v] = u
                    heapq.heappush(heap, (alt, v))

        self.forwarding_table = {}
        for dest in dist:
            if dest == self.addr:
                continue
            next_hop = dest
            while prev[next_hop] != self.addr:
                next_hop = prev[next_hop]
            self.forwarding_table[dest] = next_hop

    def __repr__(self):
        return f"LSrouter(addr={self.addr}, table={self.forwarding_table})"
