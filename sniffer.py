#!/usr/bin/env python
# Copyright Dario Clavijo 2017
# GPLv3
import sys
import socket
import struct

def ethmac_itoa(s):
	s = s.encode('hex')
	r = ":".join([s[i:i+2] for i in range(0, len(s), 2)])
	return r

def ipv4_itoa(s):
	r = "%d.%d.%d.%d" % (ord(s[0]),ord(s[1]),ord(s[2]),ord(s[3]))
 	return r

def proc_l3_proto(args):
	print args

def proc_ipv4_packet(frame):
	ip_header = frame[14:34]
        payload = frame[14:]

	#ip_header,payload = args
	#fields = struct.unpack("!BBHHHBBHII", ip_header)
	fields = struct.unpack("!BBHHHBBH4s4s", ip_header)

	dummy_hdrlen = fields[0] & 0xf    
	diff_services = fields[1]
	iplen    = fields[2]
	id_      = fields[3]
	flags    = fields[4] & 0xE000 >> 13
	TTL 	 = fields[5]
	protocol = fields[6]
	checksum = fields[7]
	ip_src   = fields[8]
	ip_dst   = fields[9]
	
	ip_packet = payload[0:iplen]
	ip_payload = ip_packet[20:]

        print '[IPv4]: hdr_len: %d, payload_len: %d, id: %d, ip_src: %s, ip_dst: %s, ip_proto: %s, flags: %s' % (dummy_hdrlen,iplen,id_,ipv4_itoa(ip_src),ipv4_itoa(ip_dst),hex(protocol),bin(flags).replace('0b',''))
        print "payload: %d bytes" % (len(ip_payload))

	#WIP
	#l3_proto_info = ip_proto_info(protocol)
	#short_name = l3_proto_info[protocol]['proto']
	#l3_proc_func = l3_proto_info[protocol]['disec']
	#long_name = l3_proto_info[protocol]['desc']

ip_proto_info = {
#WIP
}

eth_proto_info = {
0x0800:{'proto':'IPv4','disec':proc_ipv4_packet,'desc':'Internet Protocol version 4 (IPv4)'},
0x0806:{'proto':'ARP','disec':None,'desc':'Address Resolution Protocol (ARP)'},
0x0842:{'proto':'WOL','disec':None,'desc':'Wake-on-LAN[7]'},
0x22F3:{'proto':'','disec':None,'desc':'IETF TRILL Protocol'},
0x6003:{'proto':'','disec':None,'desc':'DECnet Phase IV'},
0x8035:{'proto':'','disec':None,'desc':'Reverse Address Resolution Protocol'},
0x809B:{'proto':'','disec':None,'desc':'AppleTalk (Ethertalk)'},
0x80F3:{'proto':'','disec':None,'desc':'AppleTalk Address Resolution Protocol (AARP)'},
0x8100:{'proto':'802.1Q','disec':None,'desc':'VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq[8]'},
0x8137:{'proto':'','disec':None,'desc':'IPX'},
0x8204:{'proto':'','disec':None,'desc':'QNX Qnet'},
0x86DD:{'proto':'IPv6','disec':None,'desc':'Internet Protocol Version 6 (IPv6)'},
0x8808:{'proto':'','disec':None,'desc':'Ethernet flow control'},
0x8819:{'proto':'','disec':None,'desc':'CobraNet'},
0x8847:{'proto':'MPLS','disec':None,'desc':'MPLS unicast'},
0x8848:{'proto':'MPLS','disec':None,'desc':'MPLS multicast'},
0x8863:{'proto':'PPPoE','disec':None,'desc':'PPPoE Discovery Stage'},
0x8864:{'proto':'PPPoE','disec':None,'desc':'PPPoE Session Stage'},
0x8870:{'proto':'JUMBO','disec':None,'desc':'Jumbo Frames (Obsoleted draft-ietf-isis-ext-eth-01)'},
0x887B:{'proto':'','disec':None,'desc':'HomePlug 1.0 MME'},
0x888E:{'proto':'802.1X','disec':None,'desc':'EAP over LAN (IEEE 802.1X)'},
0x8892:{'proto':'','disec':None,'desc':'PROFINET Protocol'},
0x889A:{'proto':'','disec':None,'desc':'HyperSCSI (SCSI over Ethernet)'},
0x88A2:{'proto':'','disec':None,'desc':'ATA over Ethernet'},
0x88A4:{'proto':'','disec':None,'desc':'EtherCAT Protocol'},
0x88A8:{'proto':'','disec':None,'desc':'Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq[8]'},
0x88AB:{'proto':'','disec':None,'desc':'Ethernet Powerlink[citation needed]'},
0x88B8:{'proto':'','disec':None,'desc':'GOOSE (Generic Object Oriented Substation event)'},
0x88B9:{'proto':'GSE','disec':None,'desc':'GSE (Generic Substation Events) Management Services'},
0x88BA:{'proto':'','disec':None,'desc':'SV (Sampled Value Transmission)'},
0x88CC:{'proto':'','disec':None,'desc':'Link Layer Discovery Protocol (LLDP)'},
0x88CD:{'proto':'','disec':None,'desc':'SERCOS III'},
0x88E1:{'proto':'','disec':None,'desc':'HomePlug AV MME[citation needed]'},
0x88E3:{'proto':'','disec':None,'desc':'Media Redundancy Protocol (IEC62439-2)'},
0x88E5:{'proto':'802.1AE','disec':None,'desc':'MAC security (IEEE 802.1AE)'},
0x88E7:{'proto':'','disec':None,'desc':'Provider Backbone Bridges (PBB) (IEEE 802.1ah)'},
0x88F7:{'proto':'PTP','disec':None,'desc':'Precision Time Protocol (PTP) over Ethernet (IEEE 1588)'},
0x88FB:{'proto':'','disec':None,'desc':'Parallel Redundancy Protocol (PRP)'},
0x8902:{'proto':'802.1ag','disec':None,'desc':'IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)'},
0x8906:{'proto':'FCoE','disec':None,'desc':'Fibre Channel over Ethernet (FCoE)'},
0x8914:{'proto':'FCoE','disec':None,'desc':'FCoE Initialization Protocol'},
0x8915:{'proto':'RoCE','disec':None,'desc':'RDMA over Converged Ethernet (RoCE)'},
0x891D:{'proto':'','disec':None,'desc':'TTEthernet Protocol Control Frame (TTE)'},
0x892F:{'proto':'','disec':None,'desc':'High-availability Seamless Redundancy (HSR)'},
0x9000:{'proto':'','disec':None,'desc':'Ethernet Configuration Testing Protocol[9]'},
0x9100:{'proto':'802.1Q','disec':None,'desc':'VLAN-tagged (IEEE 802.1Q) frame with double tagging'}
}

def proc_eth_frame(args):
        frame,sa_ll = args
	eth_header = struct.unpack("!6s6sH", frame[0:14])
	dummy_eth_protocol = socket.ntohs(eth_header[2])
	eth_type = eth_header[2]
	
	short_name = eth_proto_info[eth_type]['proto']
	l2_proc_func = eth_proto_info[eth_type]['disec']
	long_name = eth_proto_info[eth_type]['desc']

        if l2_proc_func != None:
    	    if eth_type == 0x800: #IPv4
                print "[ETH]: src_mac: %s, dst_mac: %s, eth_type: %s, Name: %s" % (ethmac_itoa(eth_header[0]),ethmac_itoa(eth_header[1]),hex(eth_type),short_name)
                l2_proc_func(frame)
        else:
            print "[%s] " % short_name
		
def main():
	proc_raw=True
	bin_mode=False
        iface = sys.argv[1]

	sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
	sock.bind((iface,0))

	while True:
		raw_data,sa_ll = sock.recvfrom(65535)
		if len(raw_data) <= 0:
                	break
		if proc_raw:
			proc_eth_frame((raw_data,sa_ll))
		else:
			if bin_mode:
				print raw_data
			else:
				print raw_data.encode('hex')
main()
