#! /usr/bin/python3

import sys, socket, subprocess, hashlib, re, time
from optparse import OptionParser, OptionValueError

# default parameters
default_ip = '127.0.0.1'
default_port = 40023
default_server_string = "127.0.0.1:50023"
default_server_file = "server_file.txt"
default_outfile_string = "client_file.txt"
default_queuing_delay = 0.1
default_serialization_delay = 0.001

# constants
congest_preamble="**Congest-dropped**"

# Network processing #

class PacketProcessor:
  def __init__(self):
    self.client_packets = 0
    self.dropclientpkts = []
    self.server_packets = 0
    self.dropserverpkts = []

  def set_client_pkts_to_drop(self,listpktsno):
    self.dropclientpkts = listpktsno

  def set_server_pkts_to_drop(self,listpktsno):
    self.dropserverpkts = listpktsno

  def change_ack_number(self,data,value_change):
    m = re.match(".*ACK (\d+).*",data.decode())
    ackno = m.group(1)
    return data.decode().replace("ACK {}".format(ackno),"ACK {}".format(int(ackno)+value_change),1).encode()

  def process_client_packet(self,data):
    self.client_packets += 1
    if str(self.client_packets) in self.dropclientpkts:
      return None
    return data

  def process_server_packet(self,data):
    client_address_list = data.decode().split("]")[0].lstrip("[").split(":")
    client_address = (client_address_list[0],int(client_address_list[1]))
    payload = data.decode().split("]")[1]
    new_data = data
    self.server_packets += 1
    if str(self.server_packets) in self.dropserverpkts:
      new_data = None
    return (client_address,new_data)

# Network buffering #

class PacketBuffer:
  def __init__(self):
    self.dampening = 0
    self.set_size(sys.maxsize)
    self.queue = []

  def set_size(self,num_packets):
    self.size = max(num_packets,1)
    self.reset_available_space()

  def get_size(self):
    return self.size

  def increase_dampening(self,num_packets):
    self.dampening += num_packets
    self.dampening = min(self.size-1,self.dampening)
    self.reset_available_space()

  def decrease_dampening(self,num_packets):
    self.dampening -= num_packets
    self.dampening = max(0,self.dampening)
    self.reset_available_space()

  def get_dampening(self):
    return self.dampening

  def reset_available_space(self):
    self.available_space = self.size - self.dampening

  def enqueue(self, data, sender_address):
    textdata = data.decode().strip()
    send_back = False
    if self.available_space <= 0:
      textdata = "{} {}".format(congest_preamble,textdata)
      send_back = True
    self.queue.append((textdata.encode(),sender_address,send_back))
    self.available_space -= 1

  def dequeue(self):
    queued_data = list(self.queue)
    self.queue = []
    self.reset_available_space()
    return queued_data

  def is_empty(self):
    return len(self.queue) == 0

  def __str__(self):
    return str(self.queue)

  def __repr__(self):
    return str(self)

# Client #

class Client:
  def __init__(self,own_ipaddr,own_port):
    msg_preamble = "\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+\]"
    self.server_packets_syntax = re.compile(r'({} )(FIN|ACK|[a-zA-Z0-9]+:.*\|.*)$'.format(msg_preamble))
    self.server_filename = default_server_file
    self.received = ""
    self.ownipaddr = own_ipaddr
    self.ownport = own_port
    self.own_id = "{}:{}".format(ownipaddr,ownport)
    self.last_acked = -1
    self.current_rtx_count = 0
    self.max_num_rtx = 5
    self.client_rtx_timeout = 2
    self.next_rtx_time = -1

  def get_server_filename(self):
    return self.server_filename
  
  def start_rtx_timer(self):
    self.next_rtx_time = time.time() + self.client_rtx_timeout

  def get_next_rtx_time(self):
    return self.next_rtx_time

  def restart_rtx_count(self):
    self.current_rtx_count = 0

  def increase_rtx_count(self):
    self.current_rtx_count += 1

  def is_max_rtx_exceeded(self):
    return self.current_rtx_count >= self.max_num_rtx

  def set_failed_transfer(self):
    self.received = ""

  def get_initcwnd_message(self,value):
    return "[{}] SET-CWND: {}".format(self.own_id,value)

  def send_initcwnd(self,client_buffer,initcwnd_value):
    packet = self.get_initcwnd_message(initcwnd_value).encode()
    client_buffer.enqueue(packet,(self.ownipaddr,self.ownport))
    return packet

  def get_open_message(self):
    return "[{}] GET".format(self.own_id)

  def start_transfer(self,client_buffer):
    packet = self.get_open_message().encode()
    client_buffer.enqueue(packet,(self.ownipaddr,self.ownport))
    return packet

  def process_server_packet(self,data,client_buffer):
    transfer_finished = False
    print("Client received {}".format(data))
    if not self.server_packets_syntax.match(data.decode().strip().replace("\n","")):
      print("Client discarded packet {} because it does not have a valid syntax".format(data))
      sys.exit()
    else:
      conndata = data.decode().split("]")[0]  
      msg = data.decode().split("]")[1]
      metadata = msg.split(":")[0].strip()
      tosend = "[{}] ACK {}".format(self.own_id,metadata)
      if msg.strip() == "ACK":
        transfer_finished = True
      elif msg.strip() != "FIN":
        try:
          seqno = int(metadata)
        except ValueError as e:
          print("Client discarded packet {} because sequence number {} is not an integer".format(msg,metadata))
          return transfer_finished
        payload = ":".join(msg.split(":")[1:])
        (content,checksum) = payload.split("|")
        if seqno != self.last_acked + 1 or not check_integrity(content,checksum):
          tosend = "[{}] ACK {}".format(self.own_id,self.last_acked)
        elif content.startswith("FILENAME"):
          self.server_filename = content.split()[-1]
          self.last_acked = seqno
        else:
          self.received += content.split("\n")[0] + "\n"
          self.last_acked = seqno
      if not transfer_finished:
        client_buffer.enqueue(tosend.encode(),(self.ownipaddr,self.ownport))
    return transfer_finished

  def write_file(self,outfilename):
    with open(outfilename,"w") as f:
      f.write(self.received)

# Helper functions #

def _get_id(socket_address):
  return "[{}:{}]".format(socket_address[0],socket_address[1])

def check_integrity(string,checksum):
  return checksum == hashlib.md5(string.encode()).hexdigest()

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

def setup_option_parser():
  parser = OptionParser(add_help_option=False)
  parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                    callback=check_port, metavar="PORTNO", default=default_port,
                    help="UDP port to listen on (default: {})".format(default_port))
  parser.add_option("-a", "--address", dest="ip", type="string", action="callback",
                    callback=check_address, metavar="IPNO", default=default_ip,
                    help="IP port to listen on (default: {})".format(default_ip))
  parser.add_option("-s", "--server-address", dest="srv_addr_string", type="string",
                    action="store", default=default_server_string,
                    help="server address (default: {})".format(default_server_string))
  parser.add_option("-o", "--output-file", dest="outfile_string", type="string",
                    action="store", default=default_outfile_string,
                    help="output filename (default: {})".format(default_outfile_string))
  parser.add_option("--set-server-initcwnd", dest="initcwnd", type="int", action="store", metavar="INITCWND",
                    help="number of packets that we ask the server to send as response to the first GET (if not specified, we let the server choose)")
  parser.add_option("--drop-client-packets", dest="dropclpkts", type="string", action="store", default=None)
  parser.add_option("--drop-server-packets", dest="dropsrvpkts", type="string", action="store", default=None)
  parser.add_option("--set-queue-delay", dest="queuingdel", type="string", action="store", default=None)
  parser.add_option("--set-serialization-delay", dest="serialdel", type="string", action="store", default=None)
  parser.add_option("--set-server-buffer-size", dest="srvbuffersize", type="int", action="store", default=None)
  parser.add_option("--set-server-buffer-size-changes", dest="srvbufferchanges", type="string", action="store", 
                    default="", help="specification of buffer size changes with format: \
                    'change_modifier1'@'round_with_server_packets1',...,'change_modifierN'@'round_with_server_packetN' \
                    (e.g., +1@2,-2@5)")
  return parser

def setup_packet_processor(options):
  network_processing = PacketProcessor()
  if options.dropclpkts:
    clientpkts2drop = list(options.dropclpkts.split(","))
    network_processing.set_client_pkts_to_drop(clientpkts2drop)
  if options.dropsrvpkts:
    serverpkts2drop = list(options.dropsrvpkts.split(","))
    network_processing.set_server_pkts_to_drop(serverpkts2drop)
  return network_processing

def setup_buffers(options):
  server_buffer_changes = dict()
  client_buffer = PacketBuffer()
  server_buffer = PacketBuffer()
  if options.srvbuffersize:
    server_buffer.set_size(int(options.srvbuffersize))
  if len(options.srvbufferchanges) > 0:
    for substring in options.srvbufferchanges.split(","):
      entity = int(substring.split("@")[0].strip())
      server_packet = int(substring.split("@")[1].strip())
      server_buffer_changes[server_packet] = entity
  queuing_delay = default_queuing_delay
  if options.queuingdel:
    queuing_delay = float(options.queuingdel)
  serialization_delay = default_serialization_delay
  if options.serialdel:
    serialization_delay = float(options.serialdel)
  return (client_buffer,server_buffer,server_buffer_changes,queuing_delay,serialization_delay)

def simulate_network_queuing(queuing_delay,client_buffer,server_buffer):
  init_time = time.time()
  run_queuing_cycle(init_time,queuing_delay,client_buffer,server_buffer)

def run_queuing_cycle(init_time,queuing_delay,client_buffer,server_buffer):
  try:
    elapsed_time = 0
    while elapsed_time <= queuing_delay:
      if queuing_delay > 0:
        sock.settimeout(queuing_delay - elapsed_time)
      (data, sender_address,) = sock.recvfrom(512)
      if sender_address != server_address:    # data from client
        client_buffer.enqueue(data, sender_address)
      else:                                   # data from server
        server_buffer.enqueue(data, sender_address)
      elapsed_time = time.time() - init_time
  except socket.timeout:
    pass

def process_data_from_client(network_processing,client,client_buffer,sock,server_address):
  last_transmitted = None
  for (data,sender_address,send_back) in client_buffer.dequeue():
    fwd_data = network_processing.process_client_packet(data)
    destination = server_address
    if send_back:
      destination = sender_address
    if fwd_data:
      last_transmitted = fwd_data
      client.start_rtx_timer()
      print("Forwarding {} from {} to {}".format(fwd_data,sender_address,destination))
      sock.sendto(fwd_data,destination)
  return last_transmitted

def process_data_from_server(network_processing,client,server_buffer,client_buffer,sock,server_address):
  curr_srv_packets = 0
  curr_processed = 0
  all_ecn_packets = []
  transfer_finished = False
  for (origin_data,sender_address,send_back) in server_buffer.dequeue():
    curr_processed += 1
    (_,data) = network_processing.process_server_packet(origin_data)
    if not data:
      continue
    curr_srv_packets += 1
    if send_back:
      all_ecn_packets.append(origin_data)
    elif curr_processed * serialization_delay > queuing_delay:
      server_buffer.enqueue(origin_data,sender_address)
      curr_srv_packets -= 1    # not counting this packet as it is not processed yet
    else:
      client.restart_rtx_count()
      transfer_finished = client.process_server_packet(data,client_buffer)
  if len(all_ecn_packets) > 0:
    pktdata = all_ecn_packets[-1]
    print("Forwarding back congestion-dropped packet {}".format(pktdata))
    sock.sendto(pktdata,server_address)
  return (curr_srv_packets,len(all_ecn_packets),transfer_finished)

def output_stats(server_filename):
  print("\nStats for file transfer")
  diffcmd = subprocess.Popen(["diff","-y","-w","--suppress-common-lines",outfilename,server_filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  output, errors = diffcmd.communicate()
  diffcmd.wait()
  if errors:
    raise Exception("errors while running diff:\n{}".format(errors))
  if len(output) == 0:
    print("# different lines in client file --> 0")
  else:
    output_lines = output.decode().rstrip().split("\n")
    difflines = len(output_lines)
    print("# different lines in client file --> {}".format(difflines))
    if difflines > 0:
      print("diff between client (left) and server (right) files:\n{}".format("\n".join(output_lines)))
  print("# server packets received by client (all windows) --> {}".format(server_packet_bursts))
  first_window = 0
  if server_packet_bursts != None and len(server_packet_bursts) > 0:
    first_window = server_packet_bursts[0]
  print("# server packets in first window --> {}".format(first_window))
  print("# buffer overflown packets --> {}".format(tot_ecn_packets))
  print("# total server packets --> {}".format(tot_srv_packets))
  print("# RTTs to complete flow --> {}".format(total_rounds))
  print("# server packets after the file transfer completed --> {}".format(additional_srv_packets))
  sys.stdout.flush()

# Main #

if __name__ == "__main__":
  # parse CLI arguments and options
  parser = setup_option_parser()
  (options, args) = parser.parse_args()
  outfilename = options.outfile_string
  server_string = options.srv_addr_string
  server_address = (server_string.split(":")[0],int(server_string.split(":")[1]))

  # create a socket to receive and send out packets
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.bind((options.ip, options.port))
  ownipaddr, ownport = sock.getsockname()
  print("%s: listening on IP %s and port %d" % (sys.argv[0], ownipaddr, ownport))
  sys.stdout.flush()

  # setup client and network simulators
  client = Client(ownipaddr,ownport)
  network_processing = setup_packet_processor(options)
  (client_buffer,server_buffer,server_buffer_changes,queuing_delay,serialization_delay) = setup_buffers(options)
  
  # initialise variables for stats tracking
  transmission_started = False
  transfer_finished = False
  tot_srv_packets = 0
  tot_ecn_packets = 0
  server_packet_rounds = 0
  server_packet_bursts = []
  total_rounds = 0

  # start transfer and process packets, simulating both queuing/congestion in the network and processing at the client
  client.start_rtx_timer()
  if options.initcwnd:
    client.send_initcwnd(client_buffer,options.initcwnd)
  last_transmitted = client.start_transfer(client_buffer)
  while True:
    simulate_network_queuing(queuing_delay,client_buffer,server_buffer)
    if transmission_started:
      total_rounds += 1
    if client_buffer.is_empty() and server_buffer.is_empty():
      if client.is_max_rtx_exceeded():
        print("\nERROR: failed transfer, server not responding anymore")
        client.set_failed_transfer()
        break
      if time.time() > client.get_next_rtx_time():
        client_buffer.enqueue(last_transmitted,(ownipaddr,ownport))
        client.increase_rtx_count()
      else:
        continue
    transmission_started = transmission_started or not client_buffer.is_empty()
    print()
    last_packet = process_data_from_client(network_processing,client,client_buffer,sock,server_address)
    if last_packet:
      last_transmitted = last_packet
    (num_new_srv_packets,num_new_ecn_packets,transfer_finished) = process_data_from_server(network_processing,client,server_buffer,client_buffer,sock,server_address)
    tot_srv_packets += num_new_srv_packets
    tot_ecn_packets += num_new_ecn_packets
    if num_new_srv_packets > 0:
      server_packet_rounds += 1
      server_packet_bursts.append(num_new_srv_packets - num_new_ecn_packets)
      if num_new_ecn_packets > 0:
        added_dampening = max(1,num_new_ecn_packets/2)
        server_buffer.increase_dampening(int(added_dampening))
      else:
        server_buffer.decrease_dampening(1)
      if server_packet_rounds in server_buffer_changes:
        server_buffer.set_size(server_buffer.get_size() + server_buffer_changes[server_packet_rounds])
        server_buffer_changes.pop(server_packet_rounds)
    if transfer_finished:
      break

  # checking if the server sends us additional (useless) packets
  print("\nWaiting to fully close the connection...")
  additional_srv_packets = 0
  waiting_timeout = 2
  elapsed_time = 0
  init_time = time.time()
  while waiting_timeout > elapsed_time:
    try:
      sock.settimeout(waiting_timeout - elapsed_time)
      (data, sender_address,) = sock.recvfrom(512)
      if sender_address == server_address:
        additional_srv_packets += 1
      elapsed_time = time.time() - init_time
    except socket.timeout:
      break

  # final operations
  client.write_file(outfilename)
  total_rounds += 1         # this is to compensate the first round not being counted otherwise
  output_stats(client.get_server_filename())

