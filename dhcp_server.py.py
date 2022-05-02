from socket import *
from ipaddress import *
import json

DEBUG_MODE = True
BUFF_SIZE = 1024 
SERVER_PORT = 67
CLIENT_PORT = 68
DHCP_DISCOVER = 1
DHCP_REQUEST = 3
CONFIG_FILE = 'config.json'


def debug(msg):
	if DEBUG_MODE :
		print("{0}".format(msg))

class DHSERVER(object):

	
	def config(self, configuration ):
		#self.server 
		self.ipofserver = configuration["server"] 
		self.gateway = configuration["gateway"]  
		self.subnet_mask = configuration["submask"]  
		self.addr_manager = IpConvert(self.ipofserver, self.gateway, self.subnet_mask, configuration["range"] )
		self.broadcast_address = self.addr_manager.BROADCASTaddr_get()
		self.lease_time = configuration["time"]
		self.dns = [inet_aton(configuration["dns"][i]) for i in range(len( configuration["dns"] ))]
		self.server_option = 0

	def start(self):
		self.config = socket(AF_INET, SOCK_DGRAM)
		self.config.setsockopt(SOL_IP, SO_REUSEADDR, 1)
		self.config.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
		self.config.bind((self.ipofserver, SERVER_PORT))

		while True:
			dest = ('<broadcast>', CLIENT_PORT)
			print("DHCP server is serving:")

			packet, address = self.config.recvfrom(BUFF_SIZE)
			dhcpoptions = self.packet_analyzer(packet)[13] 		#Récupération des options
			dhcpMessageType = dhcpoptions[2] 		#Type de message reçu
			ipdhcprequeste = False
			for i in range(len(dhcpoptions)):
				if(dhcpoptions[i:i+2] == bytes([50, 4])):
					dhcpRequestedIp = self.ipaddrform(dhcpoptions[i+2:i+6])

			xid, ciaddr, chaddr, magic_cookie = self.packet_analyzer(packet)[4], self.packet_analyzer(packet)[7], self.packet_analyzer(packet)[11], self.packet_analyzer(packet)[12]
			dhcpClientMacAddress = self.macaddrform(chaddr)
			debug(dest)

			if dhcpMessageType == DHCP_DISCOVER : 	#Si client envoie DHCP Discover
				print("Recv DHCP discovery, send DHCP offer:")
				try:
					ip = self.addr_manager.IP_get(str(dhcpClientMacAddress), ipdhcprequeste)					
					data = self.set_dhoffer( xid, ciaddr, chaddr, magic_cookie, ip)
					self.config.sendto(data, dest)

				except Exception as e: 
					print(e)

			elif dhcpMessageType == DHCP_REQUEST : 		#Si client envoie un DHCP Request
				print("Recv DHCP request, send ACK")
				try:
					ip = self.addr_manager.IP_get(str(dhcpClientMacAddress), ipdhcprequeste)					
					data = self.set_dhack( xid, ciaddr, chaddr, magic_cookie, ip)
					self.config.sendto(data, dest)

				except Exception as e: 
					print(e)

			else:
				print("unknown error")
		
		#print("DHCP server stoped")	


	#### Server Methods
	def ipaddrform(self, address):
		return ('{}.{}.{}.{}'.format(*bytearray(address)))

	def macaddrform(self, address):
		address = address.hex()[:16]
		return (':'.join(address[i:i+2] for i in range(0,12,2)))

	def packet_analyzer(self, packet): 	#récupération du message discover d'un client
		OP = packet[0]
		HTYPE = packet[1]
		HLEN = packet[2]
		HOPS = packet[3]
		XID = packet[4:8]
		SECS = packet[8:10]
		FLAGS = packet[10:12]
		CIADDR = packet[12:16]
		YIADDR = packet[16:20]
		SIADDR = packet[20:24]
		GIADDR = packet[24:28]
		CHADDR = packet[28:28 + 16 + 192]
		magic_cookie = packet[236:240]
		DHCPoptions = packet[240:]

		return OP, HTYPE, HLEN, HOPS, XID, SECS, FLAGS, CIADDR, YIADDR, SIADDR, GIADDR, CHADDR, magic_cookie, DHCPoptions

	def set_dhoffer(self, xid, ciaddr, chaddr, magicookie, ip): # DHCP offer packet
		OP = bytes([0x02])
		HTYPE = bytes([0x01])
		HLEN = bytes([0x06])
		HOPS = bytes([0x00])
		XID = xid
		SECS = bytes([0x00, 0x00])
		FLAGS = bytes([0x00, 0x00])
		CIADDR = ciaddr
		YIADDR = inet_aton(ip) 		# Adresse à donner au client
		SIADDR = inet_aton(self.ipofserver)
		GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		CHADDR = chaddr
		magic_cookie = magicookie
		DHCPoptions1 = bytes([53, 1, 2])
		DHCPoptions2 = bytes([1 , 4]) + inet_aton(self.subnet_mask)		# subnet_mask 255.255.255.0
		DHCPoptions3 = bytes([3 , 4 ]) + inet_aton(self.gateway) 	# gateway/router
		DHCPOptions4 = bytes([51 , 4]) + ((self.lease_time).to_bytes(4, byteorder='big')) 	#IP address lease time
		DHCPOptions5 = bytes([54 , 4]) + inet_aton(self.ipofserver) 	# DHCP server
		DHCPOptions6 = bytes([6, 4 * len(self.dns)]) 		#DNS servers ex 7.7.7.7 ou 8.8.8.8
		for i in self.dns:
			DHCPOptions6 += i
		ENDMARK = bytes([0xff])

		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + magic_cookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 + DHCPOptions4 + DHCPOptions5 + DHCPOptions6 + ENDMARK
		return package

	def set_dhack(self, xid, ciaddr, chaddr, magicookie, ip): # DHCP ACK packet
		OP = bytes([0x02])
		HTYPE = bytes([0x01])
		HLEN = bytes([0x06])
		HOPS = bytes([0x00])
		XID = xid 		#dynamique
		SECS = bytes([0x00, 0x00])
		FLAGS = bytes([0x00, 0x00])
		CIADDR = ciaddr 
		YIADDR = inet_aton(ip) 		#Adresse à donner au client
		SIADDR = inet_aton(self.ipofserver)
		GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
		CHADDR = chaddr
		Magiccookie = magicookie
		DHCPoptions1 = bytes([53 , 1 , 5]) 		#DHCP ACK(value = 5)
		DHCPoptions2 = bytes([1 , 4]) + inet_aton(self.subnet_mask)		# subnet_mask 255.255.255.0
		DHCPoptions3 = bytes([3 , 4 ]) + inet_aton(self.gateway) 	# gateway/router
		DHCPoptions4 = bytes([51 , 4]) + ((self.lease_time).to_bytes(4, byteorder='big')) 	#IP address lease time
		DHCPoptions5 = bytes([54 , 4]) + inet_aton(self.ipofserver) 		# DHCP server
		DHCPOptions6 = bytes([6, 4 * len(self.dns)]) 	# DNS servers
		for i in self.dns:
			DHCPOptions6 += i
		ENDMARK = bytes([0xff])

		package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + Magiccookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 + DHCPoptions4 + DHCPoptions5 + DHCPOptions6 + ENDMARK
		return package

class IpConvert(object):
	def __init__(self, _ipofserver, _gateway, _subnet_mask, _range):
		addr = [int(x) for x in _ipofserver.split(".")]
		debug(addr)
		mask = [int(x) for x in _subnet_mask.split(".")]
		debug(mask)
		cidr = sum((bin(x).count('1') for x in mask))
		netw = [addr[i] & mask[i] for i in range(4)]
		bcas = [(addr[i] & mask[i]) | (255^mask[i]) for i in range(4)]
		print("Network: {0}".format('.'.join(map(str, netw))))
		print("DHCP server: {0}".format(_ipofserver))
		print("Gateway/Router: {0}".format(_gateway))
		print("Broadcast: {0}".format('.'.join(map(str, bcas))))
		print("Mask: {0}".format('.'.join(map(str, mask))))
		print("Cidr: {0}".format(cidr))
		
		#convert to str format
		netw = '.'.join(map(str, netw))
		bcas = '.'.join(map(str, bcas))
		start_addr = int(ip_address(netw).packed.hex(), 16) + 1
		end_addr = int(ip_address(bcas).packed.hex(), 16) if (int(ip_address(netw).packed.hex(), 16) + 1 +_range) > int(ip_address(bcas).packed.hex(), 16) else int(ip_address(netw).packed.hex(), 16) + 1 + _range #ternary operation for range limit 
		self.list = {}
		self.broadcast = bcas
		self.allocated = 2		#2 on compte le routeur et le serveur

		for ip in range(start_addr, end_addr):
			self.IPadd(ip_address(ip).exploded, 'null') 

		self.IPupdate(_gateway, "gateway")			
		self.IPupdate(_ipofserver, "DHCP server")	

    #method SET
	def IPadd(self, ip, mac_address):				
		self.list[ip] = mac_address
		self.allocated += 1							
		return

	def IPupdate(self, ip, mac_address):
		if mac_address not in self.list.values():
			self.allocated -= 1						

		self.list.update({ip: mac_address})		#update l'adresse mac liee a l'adresse ip
		return

	def BROADCASTaddr_get(self):					
		return self.broadcast

	def IP_get(self, mac_address, ip): 
		for cle, valeur in self.list.items() :		
			if(valeur == mac_address):				
				return cle						

		if(ip != False):		#si on demande une adresse specifique alors on regarde si elle est deja attribue 
			if(self.list.get(ip) == "null"):	#si libre on renvoie l'adresse specifiee
				return ip 						

		return self.IP_free_get()		#sinon on appele la fonction d'allocation d'ip

	def IP_free_get(self):						
		for cle, valeur in self.list.items() :		
			if(valeur == "null"):					
				return cle
		return False							


if __name__ == '__main__':
	
	file = open(CONFIG_FILE)
	configuration = json.load(file)
	
	dhserver = DHSERVER()
	dhserver.config(configuration)
	dhserver.start()