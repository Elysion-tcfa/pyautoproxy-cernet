import socket, sys, select, SocketServer, struct, time

class ProxyException(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)
def parsedns(domain, flag1, server, flag2):
	if flag2:
		sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
	else:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	if flag1:
		ch = '\x1c'
	else:
		ch = '\x01'
	msg = b'\x05\x16\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
	msg += reduce(lambda x, y: x + chr(len(y)) + y, ("." + domain).split('.'))
	msg += b'\x00\x00' + ch + b'\x00\x01'
	msgr = None
	for i in range(0,5):
		sock.sendto(msg, (server, 53))
		if select.select([sock], [], [], 5)[0]:
			msgr = sock.recv(65536)
			break
	sock.close()
	if msgr == None: raise ProxyException("cannot connect to dns server")
	if ord(msgr[3]) % 16 != 0: raise ProxyException("cannot get host")
	num = struct.unpack(">H", msgr[6: 8])[0]
	msgr = msgr[len(msg): ]
	while num > 0:
		pos = msgr.find('\x00')
		if msgr[pos + 1] == ch:
			if flag1:
				return socket.inet_ntop(socket.AF_INET6, msgr[pos + 10: pos + 26])
			else:
				return socket.inet_ntop(socket.AF_INET, msgr[pos + 10: pos + 14])
		else:
			msgr = msgr[pos + 10 + ord(msgr[pos + 9]): ]
		num -= 1
	raise ProxyException("cannot get host")

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer): pass
class Socks5Server(SocketServer.StreamRequestHandler):
	def handle_tcp(self, sock, remote):
		fdset = [sock, remote]
		while True:
			r, w, e = select.select(fdset, [], [])
			if sock in r:
				msg = sock.recv(4096)
				time.sleep(0.0001)
				if len(msg) == 0 or remote.sendall(msg) != None: break
			if remote in r:
				msg = remote.recv(4096)
				time.sleep(0.0001)
				if len(msg) == 0 or sock.sendall(msg) != None: break
	def recvall(self, sock, count):
		data = ""
		while len(data) < count:
			d = sock.recv(count - len(data))
			if not d: raise ProxyException("connection closed unexpectedly")
			data = data + d
		return data
	def tcp_ipv6(self, addr, port):
		reply = b"\x05\x00\x00\x04"
		remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
		remote.connect((addr, port))
		local = remote.getsockname()
		reply += socket.inet_pton(socket.AF_INET6, local[0]) + struct.pack(">H", local[1])
		return (remote, reply)
	def tcp_ipv4(self, addr, port):
		remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		remote.settimeout(5)
		remote.connect((addr, port))
		remote.settimeout(None)
		reply = b"\x05\x00\x00\x01"
		local = remote.getsockname()
		reply += socket.inet_pton(socket.AF_INET, local[0]) + struct.pack(">H", local[1])
		return (remote, reply)
	def handle(self):
		try:
			print 'socks connection from ', self.client_address
			sock = self.connection
			# 1. Version
			sock.recv(512)
			sock.sendall(b"\x05\x00");
			# 2. Request
			if not select.select([sock], [], [], 5)[0]: return
			data = self.recvall(sock, 4)
			mode = ord(data[1])
			addrtype = ord(data[3])
			if addrtype == 1:  # IPv4
				data += self.recvall(sock, 4)
				addr = socket.inet_ntop(socket.AF_INET, data[4: ])
			elif addrtype == 3:	 # Domain name
				addr = self.recvall(sock, ord(self.recvall(sock, 1)[0]))
				data += addr
			elif addrtype == 4:	 # IPv6
				data += self.recvall(sock, 16)
				addr = socket.inet_ntop(socket.AF_INET6, data[4: ])
			port = struct.unpack('>H', self.recvall(sock, 2))[0]
			try:
				if mode == 1:  # 1. Tcp connect
					if addrtype == 3:  # If domain name received, first try IPv4 then IPv6
						try:
							(remote, reply) = self.tcp_ipv4(socket.gethostbyname(addr), port)
						except (socket.error, ProxyException):
							try:
								(remote, reply) = self.tcp_ipv6(addr, port)
							except (socket.error, ProxyException):
								(remote, reply) = self.tcp_ipv6(parsedns(addr, True, "2001:778::37", True), port)
					elif addrtype == 1:
						(remote, reply) = self.tcp_ipv4(addr, port)
					elif addrtype == 4:
						(remote, reply) = self.tcp_ipv6(addr, port)
					print 'Tcp connect to', addr, port
				else:
					reply = b"\x05\x07\x00" + data[3] # Command not supported
			except (socket.error, ProxyException):
				# Connection refused
				reply = b'\x05\x05\x00' + data[3] + b'\x00\x00\x00\x00\x00\x00'
			sock.sendall(reply)
			# 3. Transfering
			if reply[1] == '\x00':  # Success
				if mode == 1:  # 1. Tcp connect
					self.handle_tcp(sock, remote)
		except (socket.error, ProxyException):
			print 'socket error'
def main():
	server = ThreadingTCPServer(('', 1080), Socks5Server)
	server.serve_forever()
if __name__ == '__main__':
	main()
