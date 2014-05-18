#!/usr/bin/python

import socket
import signal
import select
import sys
import os
import inspect
from threading import Thread
import threading
import time
from time import strftime
import traceback
import string
import subprocess
import traceback
import csv
import logging
import pdb
from ctypes import *
import mptcp_sockopts_server
import struct
from struct import *

cdll.LoadLibrary('libc.so.6')
libc = CDLL('libc.so.6')
#import numpy as np

from netifaces import interfaces, ifaddresses, AF_INET

os.system("sudo ./timesyn.py")
#global
BUFSIZE = 1024*8
THISFILENAME = inspect.getfile(inspect.currentframe())
WAIT_INT = 60

#packet size need to be the same on server and client
packet_size = 1024
#packet settings: here you define how many fields and the sizes (like structs $
pktheader = struct.Struct('dd')


flagOnOff={ 'LISTEN':False }
start=0
tcp_conn=0
class tcp_info(Structure):
     _fields_  = [
	#TCP FSM state
	('tcpi_state',c_uint8),
	('tcpi_ca_state',c_uint8),
	('tcpi_retransmits',c_uint8),
	('tcpi_probes',c_uint8),
	('tcpi_backoff',c_uint8),
	('tcpi_options',c_uint8),
	('tcpi_snd_wscale',c_uint8,4),
        ('tcpi_rcv_wscale',c_uint8,4),
	
        ('tcpi_rto',c_uint32),
	('tcpi_ato',c_uint32),
	#max snd and rcv segment size
	('tcpi_snd_mss',c_uint32),
	('tcpi_rcv_mss',c_uint32),
	
        ('tcpi_unacked',c_uint32),
	('tcpi_sacked',c_uint32),
	('tcpi_lost',c_uint32),
	('tcpi_retrans',c_uint32),
	('tcpi_fackets',c_uint32),
	
        ('tcpi_last_data_sent',c_uint32),
	('tcpi_last_ack_sent',c_uint32),
	('tcpi_last_data_recv',c_uint32),
	('tcpi_last_ack_recv',c_uint32),
	
        ('tcpi_pmtu',c_uint32),
	#slow start size threshold for receiving
	('tcpi_rcv_ssthresh',c_uint32),
	#RTT and its smoothed mean deviation maximum measured in microseconds
	('tcpi_rtt',c_uint32),
	('tcpi_rttvar',c_uint32),
	#slow start size threshold for sending
	('tcpi_snd_ssthresh',c_uint32),
	#sending congestion window
	('tcpi_snd_cwnd',c_uint32),
	#dvertised Maximum Segment Size (MSS)
	('tcpi_advmss',c_uint32),
	#amount of reordering
	('tcpi_reordering',c_uint32),
	
        ('tcpi_rcv_rtt',c_uint32),
	#advertised rcv windows
	('tcpi_rcv_space',c_uint32),
	
        ('tcpi_total_retrans',c_uint32)
     ]
     
#SIGINT
def signal_handler( *args ):
	print >> sys.stderr, 'SIGINT: Quit gracefully'
	sys.exit(0)


#format value, cast
def format_value( v ):
	if isinstance(v, long):
		return str(v)
	else:
		return v


#wait, clock syn, minutes
def wait_for_min( mins ):
	print >> sys.stderr, '%s %s' % ( 'now:', time.strftime("%H:%M:%S", time.localtime(time.time())) )
	future_time = time.time() + ( mins * 60 )
	while True:
		cur_time = time.time()
		if( cur_time == future_time ):
			break
		delta = future_time - cur_time
		if( delta > 1 ):
			time.sleep(60)
			#print something to wait until...
			print >> sys.stderr, '%s %s , %s %s' % ( 'wait to sync at:', time.strftime("%H:%M:%S", time.localtime(future_time)), 'now:', time.strftime("%H:%M:%S", time.localtime(time.time())) )
		else:
			break

	
#tcpdump: start
def begin_tcpdump( iface, trace_file ):
	process = subprocess.Popen(['tcpdump', '-ttttt', '-n', '-s', '150', '-i', iface, 'tcp', '-w', trace_file])
	return process


#tcpdump: stop
def end_tcpdump( process ):
	time.sleep(3)
	#SIGTERM
	process.terminate() #process.kill()
	(stdout_data, stderr_data) = process.communicate()
	print stdout_data
	print stderr_data

#TCP socket open
def set_tcp_socket( addr, port ):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		print 'TCP socket: %s:%d' % (addr, port)
		return s
	except socket.error as e:
		if s:
			s.close() 
		print >> sys.stderr, "could not open socket: ", addr,":",port, e
		raise

#TCP socket close
def unset_tcp_socket( tcp_socket ):
	try:
		tcp_socket.close()
	except tcp_socket.error as e:
		print >> sys.stderr, "could not close socket: ", tcp_socket, e
		raise

#send
def send_socket( s, server_addr, server_port, message ):
        i=1
        remaining_msg = len(message)
        to_send = bytearray(os.urandom(min(BUFSIZE, remaining_msg)))
        while remaining_msg > 0:
                try:
                        sent_now = s.send(to_send)
                        if sent_now == 0:
                                raise RuntimeError("send: nothing sent")
                        tsend = time.time()
                        remaining_msg -= sent_now
                        sendline = '%d %s %.15g %d%s %s:%s' % (i, 'UL',  tsend, sent_now, ' Byte', server_addr, server_port)
                        print sendline
                        i+=1
                except Exception as e:
                        print >> sys.stderr, 'sendto error:', e
                        break


#receive
def recv_socket( tcp_conn, client_addr ):
	recv_data = []
	#float pktID = []
	#float send_time = []
        i = 0
	total_data = 0
        while True:
                try:
			print 'inside receiver packet header size : %d \n' % pktheader.size
                        recvready = select.select([tcp_conn], [], [], 60)
                        if recvready[0]:
                                recv_now = recv_from_socket_exact(tcp_conn, packet_size)
                                if not recv_now: break
                                trecv = time.time()
				pktID = pktheader.unpack(recv_now[:(pktheader.size)])
                                print float(pktID[0])
                                print float(pktID[1])
				#print send_time[0]

                                recvline = '%.15g %d%s' % (trecv, len(recv_now), ' Byte')
                                recv_data.append([time.time(), len(recv_now), pktID[0], pktID[1], client_addr])
				print recvline
				#print 'client address %s \n' % recvready[0]
				total_data += len(recv_now)
                                i+=1
                        else:
                                print "recv timed out!"
                                break
                except Exception as e:
                        print >> sys.stderr, 'recv error: ', e;
                        break
        print 'number times %d \n' % i
        print 'total amount of data %d Byte \n' % total_data
	return recv_data


# This function is necessary since in TCP you receive 'bytes' and not 'packets' of the same size.
def recv_from_socket_exact(s, bytes):
        recv = ''
        while bytes > 0:
                recv_now = s.recv(bytes)
                if not recv_now:
                        return None
                bytes -= len(recv_now)
                recv += recv_now
        return recv


def accept_with_timeout(socket, timeout):
	ready = select.select([socket], [], [], timeout)
	if ready[0]:
		return socket.accept()
	else:
		return (None, None)

def monitor_main(sock):
  print "Waiting for MPTCP session ..."
  session_id = mptcp_sockopts_server.wait_for_session(sock)
  print "Monitoring session {0} ...".format(session_id)

  while True:
    try:
      info = mptcp_sockopts_server.get_info(sock)
    except:
      time.sleep(0.1)
      continue

    # store samples for each subflow
    #for pi, subflow_info in info['subflows'].iteritems():
      #print pi, 'ratings', 'local', subflow_info['mptcpi_local_rating'], 'remote', subflow_info['mptcpi_remote_rating']

    # at the end of this iteration, wait 100ms
    time.sleep(0.1)

def seperate_with_PID(recv_data):
	packet_1=[]
	packet_2=[]
	for packet in recv_data:
		if(packet[2] == 1.0):
			packet_1.append(packet)
			#print packet_1
		elif(packet[2] == 2.0):
			#print 'packet 2 enter'
			packet_2.append(packet)
	log_recv_data_to_file(packet_1, 'packet_1')
	log_recv_data_to_file(packet_2, 'packet_2')



def log_recv_data_to_file(recv_data, protocol):
  log_file = "OWD-UL"+"-MPTCP-"+protocol 
  epoch = 1
  with open(log_file, "w") as csvfile:
    w = csv.writer(csvfile, delimiter='\t')
    for data in recv_data:
      recv_time           = data[0]
      received_len = data[1]
      pktID = data[2]
      send_time = data[3]
      recv_ip = data[4]
      w.writerow([epoch, recv_time, received_len, pktID,  send_time, recv_ip])


#server
def server( *args ):
	finish = 0
	server_addr = args[0]
	server_port = args[1]
	protocol = args[2]
	
	try:
		global start
		flagOnOff['LISTEN'] = False
		
		global tcp_conn
		global ssh_thread
		global server_address
		global s_port
	        try:
			#tcpdump
			trace_file = ''.join(['trace-SERVER-'+protocol])
			dump = begin_tcpdump('any', trace_file)
					
			time.sleep(5)
			#TCP socket
                        tcp_socket = set_tcp_socket( server_addr, server_port )
                        tcp_socket.bind(('', server_port))
                        tcp_socket.listen(1)

                        tcp_conn, addr = accept_with_timeout(tcp_socket, 15 * 60) #tcp_socket.accept()
		        #thread that monitors the subflows
                        monitor = threading.Thread(target=monitor_main, args=(tcp_conn,))
                        monitor.daemon = True
                        monitor.start()
                        print 'TCP connection: %s:%d' % (addr[0], addr[1]) + '\n'

                        if tcp_conn:
                                #print 'TCP connection: %s:%d' % (addr[0], addr[1]) + '\n'

                                #recv: ON
                                print >> sys.stderr, '\n', 'SERVER - RECV'
                                recv_data = recv_socket(tcp_conn, addr[0])
                                unset_tcp_socket(tcp_conn)
				
                        else:
                                print >> sys.stderr, '\n', 'SERVER - TIMED OUT'
	
			
			#TCP socket, pause ss and tcp_opt and stop tcpdump
			seperate_with_PID(recv_data)
			end_tcpdump( dump )
			flagOnOff['LISTEN'] = False
			log_recv_data_to_file(recv_data, protocol)
			unset_tcp_socket(tcp_socket)
			print >> sys.stderr, '\n', 'SERVER - DONE'


		except:
			e = sys.exc_info()
			for file, linenr, function, text in traceback.extract_tb(e[2]):
				error = '%s %s %s %s %s %s %s' % (file, 'line', linenr, 'in', function, '->', e[:2])
				print >> sys.stderr, error;			
		
                                         
	except( KeyboardInterrupt, SystemExit ):
		print >> sys.stderr, 'close tcp socket: Exit! -> ',str(THISFILENAME);
	finally:
		error = '%s %s' % ('close tcp socket -> ',str(THISFILENAME))
		print >> sys.stderr, error
		try:
			tcp_socket.close()
			listentomulti.multi_dict.clear()
		except:
			pass		


#usage:
def usage():
	print >> sys.stderr, '\n' + str(THISFILENAME)+" [server IP] [server port] [protocol] " + '\n'
	sys.exit(0)


#SERVER:
if __name__ == '__main__':

	#SIGINT 
	signal.signal(signal.SIGINT, signal_handler)

	if( len(sys.argv) < 4 ):
		usage()
	elif( len(sys.argv) == 4 ):
			server_addr = sys.argv[1]
			server_port = int(sys.argv[2])
			protocol = sys.argv[3]
			server(server_addr, server_port, protocol)
				

	else:
		usage()
		
