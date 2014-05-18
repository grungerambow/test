#!/usr/bin/python

import socket
import threading
import time
import sys
import traceback
import subprocess

import mptcp_sockopts

#MPTCP
subprocess.call('sysctl -w net.mptcp.mptcp_enabled=1', shell=True)

server_port = int(sys.argv[1])           #Port

def monitor_main(sock):
  print "Waiting for MPTCP session ..."
  session_id = mptcp_sockopts.wait_for_session(sock)
  print "Monitoring session {0} ...".format(session_id)

  while True:
    try:
      info = mptcp_sockopts.get_info(sock)
    except:
      time.sleep(0.1)
      continue

    # store samples for each subflow
    for path_index, subflow_info in info['subflows'].iteritems():
      print path_index, subflow_info['mptcpi_daddr'],':', subflow_info['mptcpi_dport'], '\t remote rating:', subflow_info['mptcpi_remote_rating'], '\t', subflow_info['tcpi_last_data_recv']

    # at the end of this iteration, wait 100ms
    time.sleep(0.1)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    s.bind(('', server_port))
    s.listen(1)
    (cs, caddr) = s.accept()
    try:
      
      #thread that monitors the subflows
      monitor = threading.Thread(target=monitor_main, args=(cs,))
      monitor.daemon = True
      monitor.start()
      
      while True:
        recv_now = cs.recv(1024)
        if not recv_now:
            break
    finally:
      cs.close()
finally:
    try:
      s.close()
    except:
      print traceback.print_exc()
      pass
