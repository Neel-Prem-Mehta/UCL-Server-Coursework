#! /usr/bin/python3


# TODO: add hereafter (as a comment) the description of your design according to specifications of the "Step-back task" in the CW handout.
# <a few sentences>


import sys, socket, hashlib, time
from optparse import OptionParser, OptionValueError

# default parameters
default_ip = '127.0.0.1'
default_port = 50023
if len(sys.argv) > 2:
  default_ip = sys.argv[1]
  default_port = sys.argv[2]
default_timeout = 0.5

# Helper functions #

def get_checksum(msg):
  return hashlib.md5(msg.encode()).hexdigest()

def check_port(option, opt_str, value, parser):
  if value < 32768 or value > 61000:
    raise OptionValueError("need 32768 <= port <= 61000")
  parser.values.port = value

def check_address(option, opt_str, value, parser):
  value_array = value.split(".")
  if len(value_array) < 4 or \
     int(value_array[0]) < 0 or int(value_array[0]) > 255 or \
     int(value_array[1]) < 0 or int(value_array[1]) > 255 or \
     int(value_array[2]) < 0 or int(value_array[2]) > 255 or \
     int(value_array[3]) < 0 or int(value_array[3]) > 255:
    raise OptionValueError("IP address must be specified as [0-255].[0-255].[0-255].[0-255]")
  parser.values.ip = value

# Main #
def transmit_v1(packet, ack_val, sock, sender_address):
  ack = "ACK " + str(ack_val)
  ack_recieved = False
  while not ack_recieved:
    sock.sendto(packet.encode(),sender_address)
    init_time = time.time()
    while time.time() < init_time + default_timeout:
      (data, sender_address,) = sock.recvfrom(512)
      req = data.decode().split("]")[1].strip()
      if req == ack:
        ack_recieved = True
        break
      else:
        print(req.split())
  return True


"""def transmit_continuous(packets, indices, sock, sender_address, ack_val):
  ack = "ACK " + str(ack_val)
  last_ack = "ACK " + str(ack_val-1)
  num_last_ack = 1
  ack_recieved = False
  for packet in packets[indices[0]:indices[1]]:
      sock.sendto(packet.encode(),sender_address)
  while not ack_recieved:
    init_time = time.time()
    while time.time() < init_time + default_timeout:
      (data, sender_address,) = sock.recvfrom(512)
      req = data.decode().split("]")[1].strip()
      if req == ack:
        ack_recieved = True
        break
      elif req == last_ack:
        num_last_ack = num_last_ack+1
        if num_last_ack == 3:
          break
    if ack_recieved:
      break
    for packet in packets[ack_val:indices[1]]:
      sock.sendto(packet.encode(),sender_address)
  return ack_val + 1


def transmit_burst(packets, sock, sender_address, ack_val, burst):
  if ack_val+burst < len(packets):
    indices = [ack_val, ack_val+burst]
  else:
    indices = [ack_val, len(packets)]
  
  for packet in packets[indices[0]:indices[1]]:
      sock.sendto(packet.encode(),sender_address)
      
  while ack_val < indices[1]:
    ack = "ACK " + str(ack_val)
    last_ack_val = ack_val-1
    last_ack = "ACK " + str(last_ack_val)
    num_last_ack = 1
    ack_recieved = False

    while not ack_recieved:
      init_time = time.time()
      while time.time() < init_time + default_timeout:
        (data, sender_address,) = sock.recvfrom(512)
        req = data.decode().split("]")[1].strip()
        if req == ack:
          ack_recieved = True
          break
        elif req == last_ack:
          num_last_ack = num_last_ack+1
          if num_last_ack == 3:
            break
      if ack_recieved:
        break
      for packet in packets[indices[0]:indices[1]]:
        sock.sendto(packet.encode(),sender_address)
    ack_val += 1

  return ack_val, burst"""


def transmit_burst2(packets, sock, sender_address, ack_val, burst):
  if ack_val+burst < len(packets):
    indices = [ack_val, ack_val+burst]
  else:
    indices = [ack_val, len(packets)]
  
  for packet in packets[indices[0]:indices[1]]:
      sock.sendto(packet.encode(),sender_address)

  congest = False
     
  while ack_val < indices[1]:
    ack = ack_val
    last_ack = ack_val-1
    num_last_ack = 1
    ack_recieved = False

    while not ack_recieved:
      init_time = time.time()
      while time.time() < init_time + default_timeout:
        (data, sender_address,) = sock.recvfrom(512)
        if len(data.decode().split("*")) > 2 and "Congest-dropped" == data.decode().split("*")[2]:
          congest = True
          indices[1] -= 1
        req = data.decode().split("]")[1].strip()
        if len(req) > 1 and req.split()[0] == "ACK":
          """if req.split()[1] == "FIN":
            ack_recieved = True
            ack_val = len(packets)+1
            break"""
          sent_ack = int(req.split()[1])
          if sent_ack >= ack:
            ack_recieved = True
            ack_val = sent_ack + 1
            break
          elif sent_ack == last_ack:
            num_last_ack = num_last_ack+1
            if num_last_ack == 3:
              break
      if ack_recieved:
        break
      for packet in packets[ack_val:indices[1]]:
        sock.sendto(packet.encode(),sender_address)

  if congest:
    return ack_val, burst - 1
  else:
    return ack_val, burst + 1


def transfer_files_with_ack_continuous(content, sock, client_address, sender_address, cwnd):
  ack_val = 0
  packets = []
  for index in range(len(content)):
    packet = "{} {}:{}|".format(client_address,index,content[index])
    packet += get_checksum(content[index])
    packets.append(packet)

  ack_val = transmit_continuous(packets, (0,cwnd), sock, sender_address, ack_val)
  
  for i in range(len(content) - cwnd):
    index = i+cwnd
    ack_val = transmit_continuous(packets, (index, index+1), sock, sender_address, ack_val)

  while ack_val < len(packets):
    ack_val = transmit_continuous(packets, (len(packets), len(packets)), sock, sender_address, ack_val)
    
  fin_msg = "{} FIN".format(client_address)
  sock.sendto(fin_msg.encode(),sender_address)


def transfer_files_with_ack_burst(content, sock, client_address, sender_address, cwnd):
  ack_val = 0
  burst = cwnd
  
  packets = []
  for index in range(len(content)):
    packet = "{} {}:{}|".format(client_address,index,content[index])
    packet += get_checksum(content[index])
    packets.append(packet)
  fin_msg = "{} FIN".format(client_address)
  #packets.append(fin_msg)

  while ack_val < len(packets):
    ack_val, burst = transmit_burst2(packets, sock, sender_address, ack_val, burst)
    if burst < 1:
      burst = 1
  sock.sendto(fin_msg.encode(),sender_address)


if __name__ == "__main__":
  # parse CLI arguments
  # NOTE: do NOT remove support for the following options
  parser = OptionParser()
  parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                    callback=check_port, metavar="PORTNO", default=default_port,
                    help="UDP port to listen on (default: {})".format(default_port))
  parser.add_option("-a", "--address", dest="ip", type="string", action="callback",
                    callback=check_address, metavar="IPNO", default=default_ip,
                    help="IP port to listen on (default: {})".format(default_ip))
  (options, args) = parser.parse_args()
  own_ip = options.ip
  own_port = options.port

  # create a socket for packet exchanges with the clients
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  own_address = (own_ip, own_port)
  sock.bind(own_address)

  # print that we are ready
  # NOTE: do NOT remove the following print
  print("%s: listening on IP %s and UDP port %d" % (sys.argv[0], own_ip, own_port))
  sys.stdout.flush()

  # extract content of file to transfer 
  content = []
  with open("server_file.txt") as f:
    content = f.readlines()

  cwnd = 1

  # wait for GETs from clients, and transfer file content after each request
  while True:
    (data, sender_address,) = sock.recvfrom(512)
    client_address = data.decode().split("]")[0] + "]"
    req = data.decode().split("]")[1].strip()
    print("Received {}".format(data))
    if req == "ACK FIN":
      sock.sendto("{} ACK".format(client_address).encode(),sender_address)

    if "SET-CWND" in req:
      cwnd = int(data.decode().split(":")[2].strip())
      
    if req != "GET":
      continue
    transfer_files_with_ack_burst(content, sock, client_address, sender_address, cwnd)
    cwnd = 1
