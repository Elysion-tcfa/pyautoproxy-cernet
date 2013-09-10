import socket, sys, select, SocketServer, struct, os, time
from proxylib import *
from conflib import *

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer): pass
class Socks5Server(SocketServer.StreamRequestHandler):
	def handle(self):
		global cnt
		global cache
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
					except socket.error: pass
			elif addrtype == 4:
				data += recvall(sock, 16)
				addr = inet_ntop(socket.AF_INET6, data[4: ])
			if addrtype == 4 and addr[0: 7] == '::ffff:':
				try:
					inet_pton(socket.AF_INET, addr[7: ])
					addr = addr[7: ]
					addrtype = 1
				except socket.error: pass
			port = struct.unpack('>H', recvall(sock, 2))[0]
			try:
				if mode == 1:
					remotelist = []
					flag = False
					newtype = False
					tport = port
					if tport > 1024: tport = 1024
					if (addr, tport) in cache and time.time() - cache[(addr, tport)][1] < 300:
						method = cache[(addr, tport)]
						try:
							(remote, reply) = eval('tcp_' + method[0]['type'])(method[2], method[3], port, method[0])
							remotelist = [[remote] + method]
							flag = True
						except (socket.error, ProxyException): pass
					newtype = True
					for conf in config:
						if flag: break
						if not conf['type'] in ['direct', 'http', 'http_tunnel', 'socks4', 'socks5']: continue
						if 'domainaccept' in conf and not filtered(addr, conf['domainaccept']): continue
						if 'domainexcept' in conf and filtered(addr, conf['domainexcept']): continue
						if 'port' in conf and not portrange(port, conf['port']): continue
						if conf['type'] in ['direct', 'socks4'] or ('hostname' in conf and conf['hostname'] == '0'):
							resolvelist = []
							for dnsconf in config:
								try:
									if flag: break
									if not dnsconf['type'] in ['dns_direct6', 'dns_direct4', 'dns_proxy6', 'dns_proxy4']: continue
									if conf['type'] in ['socks4'] and not dnsconf['type'] in ['dns_direct4', 'dns_proxy4']: continue
									if 'domainaccept' in dnsconf and not filtered(addr, dnsconf['domainaccept']): continue
									if 'domainexcept' in dnsconf and filtered(addr, dnsconf['domainexcept']): continue
									(af, ip) = eval('tcp' + dnsconf['type'])(addr, dnsconf)
									if af == socket.AF_INET and '4to6' in dnsconf:
										(af, ip) = (socket.AF_INET6, dnsconf['4to6'] + ':' + ip)
									if af == socket.AF_INET:
										iptype = 1
									else:
										iptype = 4
									if not (ip, iptype) in resolvelist:
										resolvelist.append((ip, iptype))
										(remote, reply) = eval('tcp_' + conf['type'])(ip, iptype, port, conf)
										remotelist.append([remote, conf, time.time(), ip, iptype])
										flag = True
								except (socket.error, ProxyException): pass
						else:
							try:
								(remote, reply) = eval('tcp_' + conf['type'])(addr, addrtype, port, conf)
								remotelist.append([remote, conf, time.time(), addr, addrtype])
								if conf['type'] != 'http':
									flag = True
							except (socket.error, ProxyException): pass
					if remotelist == []: raise ProxyException('cannot connect to host')
					print 'Tcp connect to', addr, port
				else:
					reply = '\x05\x07\x00' + data[3]
			except (socket.error, ProxyException):
				reply = '\x05\x05\x00' + data[3] + '\x00\x00\x00\x00\x00\x00'
			sock.sendall(reply)
			if reply[1] == '\x00':
				if mode == 1:
					try: conf, ts, addr, addrtype = handle_tcp(sock, remotelist)
					except: raise socket.error
					if newtype:
						cache[(addr, tport)] = [conf, ts, addr, addrtype]
					cnt += 1
					if cnt == 200:
						cnt = 0
						ts = time.time()
						newcache = {}
						for it in cache:
							if ts - cache[it][1] <= 300: newcache[it] = cache[it]
						cache = newcache
					remote.close()
		except (socket.error, ProxyException):
			print 'socket error'
			try: remote.close()
			except: pass
def main():
	server = ThreadingTCPServer(('127.0.0.1', 1080), Socks5Server)
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		server.shutdown()

os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
config = getconf()
cache = {}
cnt = 0
if __name__ == '__main__':
	main()
