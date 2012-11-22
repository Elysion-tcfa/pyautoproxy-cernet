import socket, sys, select, SocketServer, struct, os
from proxylib import *
from conflib import *

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer): pass
class Socks5Server(SocketServer.StreamRequestHandler):
	def handle(self):
		try:
			print 'socks connection from ', self.client_address
			sock = self.connection
			sock.recv(512)
			sock.sendall('\x05\x00');
			if not select.select([sock], [], [], 5)[0]: return
			data = recvall(sock, 4)
			mode = ord(data[1])
			addrtype = ord(data[3])
			if addrtype == 1:
				data += recvall(sock, 4)
				addr = inet_ntop(socket.AF_INET, data[4: ])
			elif addrtype == 3:
				addr = recvall(sock, ord(recvall(sock, 1)[0]))
				data += addr
				try:
					inet_pton(socket.AF_INET, addr)
					addrtype = 1
				except socket.error:
					try:
						inet_pton(socket.AF_INET6, addr)
						addrtype = 4
					except (socket.error, ProxyException): pass
			elif addrtype == 4:
				data += recvall(sock, 16)
				addr = inet_ntop(socket.AF_INET6, data[4: ])
			if addrtype == 4 and addr[0: 7] == '::ffff:':
				addr = addr[7: ]
				addrtype = 1
			port = struct.unpack('>H', recvall(sock, 2))[0]
			try:
				if mode == 1:
					flag = False
					for conf in config:
						try:
							if conf['type'] == 'ipv4':
								(remote, reply) = tcp_ipv4(addr, addrtype, port, conf)
							elif conf['type'] == 'ipv6':
								(remote, reply) = tcp_ipv6(addr, addrtype, port, conf)
							elif conf['type'] == 'nat64':
								(remote, reply) = tcp_nat64(addr, addrtype, port, conf)
							elif conf['type'] == 'http':
								(remote, reply) = tcp_http(addr, addrtype, port, conf)
							elif conf['type'] == 'socks4':
								(remote, reply) = tcp_socks4(addr, addrtype, port, conf)
							elif conf['type'] == 'socks5':
								(remote, reply) = tcp_socks5(addr, addrtype, port, conf)
							else: continue
							flag = True
							break
						except (socket.error, ProxyException): pass
					if not flag: raise ProxyException('cannot connect to host')
					print 'Tcp connect to', addr, port
				else:
					reply = '\x05\x07\x00' + data[3]
			except (socket.error, ProxyException):
				reply = '\x05\x05\x00' + data[3] + '\x00\x00\x00\x00\x00\x00'
			sock.sendall(reply)
			if reply[1] == '\x00':
				if mode == 1:
					handle_tcp(sock, remote)
					remote.close()
		except (socket.error, ProxyException):
			print 'socket error'
			try: remote.close()
			except: pass
def main():
	server = ThreadingTCPServer(('', 1080), Socks5Server)
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		server.shutdown()

os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
config = getconf()
if __name__ == '__main__':
	main()
