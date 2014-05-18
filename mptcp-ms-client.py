#!/usr/bin/python

import socket
import time
import csv
import threading
import sys
import traceback
import subprocess

import mptcp_sockopts

#MPTCP
subprocess.call('sysctl -w net.mptcp.mptcp_enabled=1', shell=True)

server_addr = sys.argv[1]
server_port = int(sys.argv[2])
data_amount = float(sys.argv[3])

#multistreaming patch
TCP_ALLOWED_SUBFLOW = 35

disabled_interfaces = ['ppp2', 'ppp3', 'eth1', 'eth0']

mptcp_session_id = None
def monitor_main(sock):
    global mptcp_session_id
    print "Waiting for MPTCP session ..."
    mptcp_session_id = mptcp_sockopts.wait_for_session(sock)
    print "Monitoring session {0} ...".format(mptcp_session_id)

    subflow_disabled = {}
    while True:
        info = mptcp_sockopts.get_info(sock)
        for path_index, subflow_info in info['subflows'].iteritems():
            if path_index in subflow_disabled:
              continue # already disabled

            iface = mptcp_sockopts.get_subflow_iface_from_info(info, path_index)
            if iface in disabled_interfaces:
                print 'send rating 255 on iface', iface
                mptcp_sockopts.set_rating(sock, path_index, 255)
                subflow_disabled[path_index] = True
                
        time.sleep(0.1)


def send_on_interface(s, siface):
  #1. mptcp info
  info = mptcp_sockopts.get_info(s)
  for path_index, subflow_info in info['subflows'].iteritems():

    #2. loop through all subflows
    iface = mptcp_sockopts.get_subflow_iface_from_info(info, path_index)
    
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


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((server_addr, server_port))
    
    #thread that monitors the subflows
    monitor = threading.Thread(target=monitor_main, args=(s,))
    monitor.daemon = True
    monitor.start()
    
    chunk = bytearray(['x'] * 1024)
    sent_bytes = 0
    current_send_iface = None
    while sent_bytes < (data_amount * 1024 * 1024):
      
      #Multistreaming Patch
      desired_send_iface = 'ppp0'
      if desired_send_iface != current_send_iface:
        if send_on_interface(s, desired_send_iface):
          current_send_interfae = desired_send_iface
      
      sent_now = s.send(chunk)
      print 'sent bytes:', sent_bytes
      
      if not sent_now:
        break
      sent_bytes = sent_bytes + sent_now
finally:
    s.close()
