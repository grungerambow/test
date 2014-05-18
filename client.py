#!/usr/bin/python

import socket
import signal
import sys
import os
import inspect
from threading import Thread
import time
from time import strftime
import traceback
import string
import subprocess
import csv
from ctypes import *
cdll.LoadLibrary('libc.so.6')
libc = CDLL('libc.so.6')
#import numpy as np
import shutil
import glob
import select
import struct
from struct import *



#global
BUFSIZE = 1024*8
THISFILENAME = inspect.getfile(inspect.currentframe())
WAIT_INT = 60


#packet size need to be the same on server and client
packet_size = 1024
#packet_size = 1024
#packet settings: here you define how many fields and the sizes (like structs in C)
pktheader = struct.Struct('dd') 

payload_size = (packet_size - calcsize('dd'))
payload = bytearray(os.urandom(payload_size))

flagOnOff={ 'LISTEN':False }
start=0
tcp_socket=0


#SIGINT
def signal_handler( *args ):
        print >> sys.stderr, 'SIGINT: Quit gracefully'
        sys.exit(0)


#TCP socket open (Mehraj)
def set_tcp_socket( address, port ):
	
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                print 'TCP socket: %s:%d' % (address, port)
		return s
	except socket.error as e:
		if s:
			s.close() 
		print >> sys.stderr, "could not open socket: ", address,":",port, e
		raise
	    
	    
	    
#TCP socket close
def unset_tcp_socket( tcp_socket ):
	try:
		tcp_socket.close()
	except tcp_socket.error as e:
		print >> sys.stderr, "could not close socket: ", tcp_socket, e
		raise


#send
def send_socket( s, server_addr, server_port, number ):
	i = 0
	#no = int(number)
	#nu = float(1/no)
	#print 'number of times %f, %d \n' % (nu,int(number))
	start = 0
	end = time.time() + number * 60.0
	#remaining_msg = len(message)
	#to_send = bytearray(os.urandom(min(BUFSIZE, remaining_msg)))
	#to_send = bytearray(os.urandom(min(payload_size, remaining_msg)))
	while(time.time()<=end):
		try:
			pktID = 1
			curr_time = float(time.time())
			header = pktheader.pack(pktID, curr_time)
			to_send = header + payload
			sent_now = s.send(to_send)
			if sent_now == 0:
				raise RuntimeError("send: nothing sent")
			print 'current time %f ' % curr_time
			#tsend = time.time()
			sendline = '%.15g %d%s %s:%s' % (curr_time, sent_now, ' Byte', server_addr, server_port)
			print sendline
			#time.sleep(0.1) # 10 pkts/s
			time.sleep(0.5) # 2 pkts/s
 			#start =  start + 0.2
			i+=1
		except Exception as e:
			print >> sys.stderr, 'sendto error:', e
			break
	print "number times %d \n" % i

#receive
def recv_socket( tcp_conn, message ):
	i=1
	recv_data={}
	remaining_msg = len(message)
	while remaining_msg > 0:
		try:
			recvready = select.select([tcp_conn], [], [], 60)
			if recvready[0]:
				recv_now = tcp_conn.recv(BUFSIZE)
				trecv = time.time()
				remaining_msg -= len(recv_now)
				#log recv data
				recv_data[trecv]=len(recv_now)
				i+=1
			else:
				print "recv timed out!"
				break
				
		except Exception as e:
			print >> sys.stderr, 'recv error: ', e;
			break
	return recv_data


def log_recv_data_to_file(recv_data, filename):
	sorted_timestamps = sorted(recv_data.keys())
	#log_file = "goodput-CLIENT-"+direction+"-"+filename+"-"+str(epoch)
	log_file = "goodput-CLIENT-"+filename
	with open(log_file, "a") as csvfile:
		w = csv.writer(csvfile, delimiter='\t')
		for ts in sorted_timestamps:
			received_len = recv_data[ts]
			w.writerow([ts, received_len])

#client
def client( *args ):
	finish = 0
	server_addr = args[0]
	server_port = args[1]
	number = args[2]

	try:
		#TCP socket
		tcp_socket = set_tcp_socket(server_addr, server_port)
		tcp_socket.connect((server_addr, server_port))
		print 'TCP connection: %s:%d' % (server_addr, server_port) + '\n'
					
		#send: ON
		print >> sys.stderr, '\n', 'CLIENT - SEND'
		send_socket( tcp_socket, server_addr, server_port, number )
										
		#TCP socket, pause tcp_opt and ss and close tcpdump
		flagOnOff['LISTEN'] = False
		unset_tcp_socket(tcp_socket)
		print >> sys.stderr, '\n', 'CLIENT - DONE'
					
					
	except( KeyboardInterrupt, SystemExit ):
		print >> sys.stderr, 'close tcp socket: Exit! -> ',str(THISFILENAME);
	finally:
		error = '%s %s' % ('close tcp socket -> ',str(THISFILENAME))
		print >> sys.stderr, error
		try:
			tcp_socket.close()
		except:
			pass		

#usage:
def usage():
	print >> sys.stderr, '\n' + str(THISFILENAME)+ " [server IP] [server port] [filesize] [number of times]" + '\n'
	sys.exit(0)


#CLIENT:
if __name__ == '__main__':

	#SIGINT 
	#signal.signal(signal.SIGINT, signal_handler)

	if( len(sys.argv) < 4 ):
		usage()
	elif( len(sys.argv) == 4 ):
			server_addr = sys.argv[1]
			server_port = int(sys.argv[2])
			number = float(sys.argv[3])
			#client
			client(server_addr, server_port, number)
	else:
		usage()
		
