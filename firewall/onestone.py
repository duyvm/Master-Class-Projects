#!/usr/bin/env python3
from scapy.all import *
import argparse
import swpag_client

sc= swpag_client.Team("http://52.37.204.0","08DKnpiwtqmhl0IcZkH7")
team_host_self = ["team1"]
INTERFACE = ""

# -1 means no service_id is found
def get_service_id_by_port(port):
    service_list = sc.get_service_list()
    service_ids=[s for s in service_list if s['port']==port]
    if len(service_ids)>0:
        service_id = service_ids[0]['service_id']
        return service_id
    return -1
    
#duplicate the packet and send to the target team, check if the target response packet has the flag (search for pattern like FLGXXXXXXX)
#submit the flag and not response the original tcp_packet if the target response packet has the flag
def duplicate(tcp_packet, target_team_host, target_team_flag_id, self_flag_id):
    return true

    
#forward the traffic to all teams with same service and see if any flag id response
def onestone(tcp_packet):
    if tcp_packet.haslayer('TCP'):
        tcp_dport=tcp_packet[TCP].dport
        service_id = get_service_id_by_port(tcp_dport)
        if service_id<0:
            return
        team_list = sc.get_targets(service_id)
        target_team_list = [t for t in team_list if t['hostname'] not in team_host_self] #exclude our self team
        self_team_list = [t for t in team_list if t['hostname'] in team_host_self]
        self_flag_id = -1
        if len(self_team_list)>0:
            self_flag_id = self_team_list[0]['flag_id']
        if len(target_team_list)<1:
            return
        for team in target_team_list:            
            target_team_host = team['hostname']
            target_team_flag_id = team['flag_id']
            duplicate(tcp_packet, target_team_host, target_team_flag_id, self_flag_id)
                        
        #recalculate checksum        
        #del tcp_packet[TCP].chksum
        #tcp_packet[TCP]=tcp_packet[TCP].__class__(bytes(tcp_packet[TCP]))   
        #del tcp_packet.chksum
        #tcp_packet = tcp_packet.__class__(bytes(tcp_packet))        
        #sendp(tcp_packet, iface=INTERFACE)      
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface')
    args = parser.parse_args()
    INTERFACE = args.interface
    
    sniff(prn=onestone, iface=INTERFACE)
