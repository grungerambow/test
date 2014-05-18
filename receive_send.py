
#!/usr/bin/python

import socket
import signal
import select
import sys
import os
import inspect
from threading import Thread
import time
import pcui
import threading
from time import strftime
import traceback
import string
import subprocess
import traceback
import csv
import logging
import pdb
from ctypes import *
import mptcp_sockopts_client
import struct
import pathinfo
import interfaceinfo
from struct import *
import serial
cdll.LoadLibrary('libc.so.6')
libc = CDLL('libc.so.6')
#import numpy as np

from netifaces import interfaces, ifaddresses, AF_INET

at_cmd_2g = 'AT^SYSCFG=13,0,3FFFFFFF,2,3' + '\r'
at_cmd_3g = 'AT^SYSCFG=14,2,3FFFFFFF,2,2' + '\r'

#multi und zeugs
interfaceinfo.start() # MULTI, required by pathinfo
pathinfo.start()

#MPTCP
#subprocess.call('sysctl -w net.mptcp.mptcp_enabled=1', shell=True)

#multistreaming patch
TCP_ALLOWED_SUBFLOW = 35

#global
disabled_interfaces = ['eth0', 'eth1', 'ppp2', 'ppp3']
mptcp_session_id = None
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

#TCP socket open (Mehraj)
def set_tcp_socket1( address, port, interface ):

        ip_list = []
        #for interface in interfaces():
        for link in ifaddresses(interface)[AF_INET]:
            ip_list.append(link['addr'])
            ip = ip_list[0]

        try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                #bind to ip
                s.bind((ip, 0))
                return s
        except socket.error as e:
                if s:
                        s.close()
                print >> sys.stderr, "could not open socket: ", address,":",port, e
                raise


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
	


#TCP socket close
def unset_tcp_socket( tcp_socket ):
	try:
		tcp_socket.close()
	except tcp_socket.error as e:
		print >> sys.stderr, "could not close socket: ", tcp_socket, e
		raise

#send
def send_socket( s,  recv_p):
	for packet in recv_p:
	        try:
              		sent_now = s.send(packet)
        	        if sent_now == 0:
                	       raise RuntimeError("send: nothing sent")
        	except Exception as e:
                	print >> sys.stderr, 'sendto error:', e;
	        	break


def accept_with_timeout(socket, timeout):
	ready = select.select([socket], [], [], timeout)
	if ready[0]:
		return socket.accept()
	else:
		return (None, None)


#while ( len(interfaceinfo._multi_dict) == 0 ):
  #time.sleep(1)

#write AT command to the modem
def send_command_to_modem( iface, at_cmd ):
  try:
    device = pcui.get_pcui( str(iface[-1]) )
    print device
    if device == '':
      return False
    # open serial port
    ser_port = serial.Serial(device, baudrate=115200, timeout=1, writeTimeout=1)
    try:
      #print iface, ser_port.portstr        # check which port was really used
      ser_port.write(at_cmd)
    finally:
      ser_port.close()
  except:
    traceback.print_exc()
    return False
  return True


#write AT command to the modem
def keep_modem_in_mode( iface, at_cmd, dest_mode ):
  timeout = 60.0        # 60 seconds
  timeout_time = time.time() + timeout
  while timeout_time > time.time():
    try:
      path_info = pathinfo.getinfo()
      mode = path_info[iface]['mode']
      print 'send command to modem: ', iface, mode, at_cmd
      if dest_mode not in mode:
        send_command_to_modem(iface, at_cmd)
      else:
        return
    except:
      e = sys.exc_info()
      for file, linenr, function, text in traceback.extract_tb(e[2]):
        error = '%s %s %s %s %s %s %s' % (file, 'line', linenr, 'in', function, '->', e[:2])
        print >> sys.stderr, error;
    time.sleep(2.5)


def monitor_main(sock):
    global mptcp_session_id
    print "Waiting for MPTCP session ..."
    mptcp_session_id = mptcp_sockopts_client.wait_for_session(sock)
    print "Monitoring session {0} ...".format(mptcp_session_id)

    subflow_disabled = {}
    while True:
        info = mptcp_sockopts_client.get_info(sock)
        #print 'information %s \n' % info
        for path_index, subflow_info in info['subflows'].iteritems():
            if path_index in subflow_disabled:
              continue # already disabled

            iface = mptcp_sockopts_client.get_subflow_iface_from_info(info, path_index)
            if iface in disabled_interfaces:
                print 'send rating 255 on iface', iface
                mptcp_sockopts_client.set_rating(sock, path_index, 255)
                subflow_disabled[path_index] = True

        time.sleep(0.1)

def send_on_interface(s, siface):
  #1. mptcp info
  info = mptcp_sockopts_client.get_info(s)
  print siface, 'inside ppp1\n'
  for path_index, subflow_info in info['subflows'].iteritems():

    #2. loop through all subflows
    iface = mptcp_sockopts_client.get_subflow_iface_from_info(info, path_index)
    print 'iface %s' % iface
    #3. if subflow on right interface, find and set path_index
    if iface == siface:
      
      #Multistreaming Patch: TCP_ALLOWED_SUBFLOW
      # 0     == MPTCP
      # 1...X == Modified MPTCP
      try:
        s.setsockopt(socket.IPPROTO_TCP, TCP_ALLOWED_SUBFLOW, int(subflow_info['mptcpi_path_index']))
        print 'set allowed subflow:', iface, path_index, subflow_info['mptcpi_path_index']
        return True
      except:
        print traceback.print_exc()
        pass
      return False
  try:
    s.setsockopt(socket.IPPROTO_TCP, TCP_ALLOWED_SUBFLOW, 0)
  except:
    print traceback.print_exc()
    pass
  return False

#receive
def recv_socket( tcp_conn ):
	
	i = 0
	while True:
		try:
			recvready = select.select([tcp_conn], [], [], 60)
			print recvready
			if recvready:
				recv_now = tcp_conn.recv(BUFSIZE)
				if not recv_now: break
				trecv = time.time()
				recvline = '%.15g %d%s' % (trecv, len(recv_now), ' Byte')
				print recvline
				i+=1
			else:
				print "recv timed out!"
				break
		except Exception as e:
			print >> sys.stderr, 'recv error: ', e;
			break
	print 'number times %d \n' % i

def log_recv_data_to_file(recv_data):
        sorted_timestamps = sorted(recv_data.keys())
        #log_file = "goodput-CLIENT-"+direction+"-"+filename+"-"+str(epoch)
        log_file = "goodput-CLIENT-"+time.time()
        with open(log_file, "a") as csvfile:
                w = csv.writer(csvfile, delimiter='\t')
                for ts in sorted_timestamps:
                        received_len = recv_data[ts]
                        w.writerow([received_len])

			#safe close socket
def safe_socket_close(sock):
	try:
		sock.close()
    	except:
        	pass




#server
def server( *args ):
	finish = 0
	server_addr = args[0]
	server_port1 = args[1]
	server_port2 = args[2]
	server_port3 = args[3]
	modem_mode = args[4]

	try:
		global start
		flagOnOff['LISTEN'] = False
		
		global tcp_conn
		global ssh_thread
		#global server_addr= "128.39.37.182"
	        try:

			'''if modem_mode == '2G':
  				keep_modem_in_mode( 'ppp1', at_cmd_2g, 'GSM' )
  				time.sleep(5)
			if modem_mode == '3G':
  				keep_modem_in_mode( 'ppp1', at_cmd_3g, 'WCDMA' )
  				time.sleep(5)'''
			trace_file = ''.join(['trace-CLIENT-'+modem_mode])
			dump = begin_tcpdump('any', trace_file)
					
			time.sleep(5)
			#TCP socket
                	tcp_socket3 = set_tcp_socket(server_addr, server_port3)
                	tcp_socket3.connect((server_addr, server_port3))
                	print 'TCP connection: %s:%d' % (server_addr, server_port3)
 	
			#thread that monitors the subflows
			monitor = threading.Thread(target=monitor_main, args=(tcp_socket3,))
                	monitor.daemon = True
                	monitor.start()
			current_send_iface = None

			dat = []
			#recv: ON
			print >> sys.stderr, '\n', 'SERVER - RECV'
			#TCP/IP socket Nr.: 1
			tcp_server1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			#Bind socket to port
			server_address1 = ('', server_port1)
			print 'address: %s port: %s' % server_address1
			tcp_server1.bind(server_address1)
			#Listen
			tcp_server1.listen(1)

			#TCP/IP socket Nr.: 2
			tcp_server2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			#Bind socket to port
			server_address2 = ('', server_port2)
			print 'address: %s port: %s' % server_address2
			tcp_server2.bind(server_address2)
			#Listen
			tcp_server2.listen(1)
			try:

    				(cs1, caddr1) = tcp_server1.accept()
				print 'Connected client1 %s-%s' % (cs1, caddr1)
    				(cs2, caddr2) = tcp_server2.accept()
				print 'Connected client2 %s-%s' % (cs2, caddr2)
    				try:
    					client_socks = [cs1, cs2]
        				print 'SERVER - RECV'
					while client_socks:
						try:
                					readable, wri, err = select.select(client_socks, [], [],120)
							#print readable
                					if readable:
								for sock in readable:
                    							data = sock.recv(BUFSIZE)
                                                                        tcp_socket3.send(data)

									'''try:
										pktID = pktheader.unpack(data[:(pktheader.size)])
					                                	print float(pktID[0])
									except:
										#print traceback.print_exc()
										print 'data received size: %d ' % len(data)
										pass
									#Multistreaming Patch
									desired_send_iface = 'ppp0'
                                                                        if desired_send_iface != current_send_iface:
                                                                        	if send_on_interface(tcp_socket3, desired_send_iface):
                                                                                	current_send_interfae = desired_send_iface'''
									'''#Multistreaming Patch
      									if pktID[0] == 1.0:
										desired_send_iface = 'ppp0'
      										if desired_send_iface != current_send_iface:
        										if send_on_interface(tcp_socket3, desired_send_iface):
          											current_send_interfae = desired_send_iface
										tcp_socket3.send(data)
									elif pktID[0] == 2.0:
										desired_send_iface = 'ppp1'
                                                                                if desired_send_iface != current_send_iface:
                                                                                        if send_on_interface(tcp_socket3, desired_send_iface):
                                                                                                current_send_interfae = desired_send_iface
                                                                                tcp_socket3.send(data)'''
									if not data:
										client_socks.remove(sock) # socket is done, no more data
										break
									#rem_msg_size -=1
                    							print sock, '-->', len(data)
									dat.append(data)
							else: break
						except Exception as e:
							print "recv timed out!"
							print e
							break
					print 'data received %d' % len(dat)
    				finally:
					print 'cs2 socket closed\n'
        				safe_socket_close(cs2)
					print 'cs1 socket closed\n'
        				safe_socket_close(cs1)
			finally:
				print 'tcp_server2 socket closed\n'
    				safe_socket_close(tcp_server2)
				print 'tcp_server1 socket closed\n'
    				safe_socket_close(tcp_server1)
				safe_socket_close(tcp_socket3)
			flagOnOff['LISTEN'] = False
			end_tcpdump( dump )
			#unset_tcp_socket(tcp_socket)
			#csock.close()
			print >> sys.stderr, '\n', 'SERVER - DONE'
                        #log_recv_data_to_file(recv_p)
			#send_socket(tcp_socket3, dat)

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
	print >> sys.stderr, '\n' + str(THISFILENAME)+" [server IP] [client port1] [client port2] [server port3] [2G or 3G]" + '\n'
	sys.exit(0)


#SERVER:
if __name__ == '__main__':

	#SIGINT 
	signal.signal(signal.SIGINT, signal_handler)

	if( len(sys.argv) < 6 ):
		usage()
	elif( len(sys.argv) == 6 ):
			server_addr = sys.argv[1]
			server_port1 = int(sys.argv[2])
			server_port2 = int(sys.argv[3])
			server_port3 = int(sys.argv[4])
			modem_mode = sys.argv[5]
			#server
			server(server_addr, server_port1, server_port2, server_port3, modem_mode)

	else:
		usage()
		
