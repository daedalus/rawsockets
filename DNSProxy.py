#!/usr/bin/env python
# Author Dario Clavijo 2017
# GPLv3

import socket
import struct

UDP_IP = "127.0.0.1"
UDP_PORT = 53

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)


def DNS_dissect(data,addr):
	#print len(data)
	#fmt = "HHHHHH%ds" % (len(data)-12)	
	#print fmt
	#f = struct.unpack(fmt,data1)

	#print addr,data.encode('hex')
	#print "ID,QR,QD,AN,NS,AR,payload"

	#print addr,f

	ID = data[0:2].encode('hex')
	QR = data[2:4].encode('hex')
	QD = data[4:6].encode('hex')
	AN = data[6:8].encode('hex')
	NS = data[8:10].encode('hex')
	AR = data[10:12].encode('hex')
	payload = data[12:].encode('hex')
	
	#print addr,data.encode('hex')
	print "ADDR,ID,QR,QD,AN,NS,AR,payload"
	print addr,ID,QR,QD,AN,NS,AR,payload
	
while True:
	data1, addr1 = sock.recvfrom(1024) # buffer size is 1024 bytes

	if len(data1) > 0:
		DNS_dissect(data1,addr1)
		sock2.sendto(data1, ("8.8.8.8", 53))
	
	data2, addr2 = sock2.recvfrom(1024)
		
	if len(data2) > 0:
		DNS_dissect(data2,addr2)
		sock.sendto(data2,addr1)
