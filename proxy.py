import socket, sys, select, SocketServer, struct, os, time, threading, signal
from proxylib import *
from conflib import *

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True
class Socks5Server(SocketServer.StreamRequestHandler):
	def handle(self):
		global cnt
		global cache
		global dnscache
		global lock
		global config
		curconfig = config
		try:
			print 'socks connection from ', self.client_address
			sock = self.connection
			sock.recv(512)
			sock.send('\x05\x00')
			if not select.select([sock], [], [], 30)[0]: return
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
					lock.acquire()
					if (addr, tport) in cache and time.time() - cache[(addr, tport)][0] < 300:
						method = cache[(addr, tport)][1]
						lock.release()
						for item in method:
							try:
								(remote, reply) = eval('tcp_' + item[0]['type'])(item[1], item[2], port, item[0])
								remotelist.append([remote] + item)
								flag = True
							except (socket.error, ProxyException): pass
					else:
						lock.release()
					newtype = True
					for conf in curconfig:
						if flag: break
						if not conf['type'] in ['direct', 'http', 'http_tunnel', 'socks4', 'socks5']: continue
						if 'domainaccept' in conf and not filtered(addr, conf['domainaccept']): continue
						if 'domainexcept' in conf and filtered(addr, conf['domainexcept']): continue
						if 'port' in conf and not portrange(port, conf['port']): continue
						if conf['type'] in ['direct', 'socks4'] or ('hostname' in conf and conf['hostname'] == '0'):
							resolvelist = []
							for dnsconf in curconfig:
								try:
									if flag: break
									if not dnsconf['type'] in ['dns_direct6', 'dns_direct4', 'dns_proxy6', 'dns_proxy4']: continue
									if conf['type'] in ['socks4'] and not dnsconf['type'] in ['dns_direct4', 'dns_proxy4']: continue
									if 'domainaccept' in dnsconf and not filtered(addr, dnsconf['domainaccept']): continue
									if 'domainexcept' in dnsconf and filtered(addr, dnsconf['domainexcept']): continue
									if dnsconf['type'] in ['dns_proxy4', 'dns_proxy6']:
										info = (addr, dnsconf['type'], dnsconf['server'], dnsconf['serverport'])
									else:
										info = (addr, dnsconf['type'])
									lock.acquire()
									if info in dnscache and time.time() - dnscache[info][0] < 300:
										ip, iptype = dnscache[info][1]
										lock.release()
									else:
										lock.release()
										(af, ip) = eval('tcp' + dnsconf['type'])(addr, dnsconf)
										if af == socket.AF_INET:
											iptype = 1
										else:
											iptype = 4
										lock.acquire()
										dnscache[info] = (time.time(), (ip, iptype))
										lock.release()
									if iptype == 1 and '4to6' in dnsconf:
										ip, iptype = dnsconf['4to6'] + ':' + ip, 4
									if not (ip, iptype) in resolvelist:
										resolvelist.append((ip, iptype))
										(remote, reply) = eval('tcp_' + conf['type'])(ip, iptype, port, conf)
										remotelist.append([remote, conf, ip, iptype])
										flag = True
								except (socket.error, ProxyException): pass
						else:
							try:
								(remote, reply) = eval('tcp_' + conf['type'])(addr, addrtype, port, conf)
								remotelist.append([remote, conf, addr, addrtype])
								if conf['type'] != 'http':
									flag = True
							except (socket.error, ProxyException): pass
					if remotelist == []: raise ProxyException('cannot connect to host')
					if newtype:
						lock.acquire()
						cache[(addr, tport)] = (time.time(), map(lambda x: x[1:], remotelist))
						lock.release()
					print 'Tcp connect to', addr, port
				else:
					reply = '\x05\x07\x00' + data[3]
			except (socket.error, ProxyException):
				reply = '\x05\x05\x00' + data[3] + '\x00\x00\x00\x00\x00\x00'
			sock.sendall(reply)
			if reply[1] == '\x00':
				if mode == 1:
					try: handle_tcp(sock, remotelist)
					except: raise socket.error
					for i in range(0, len(remotelist)):
						try: remotelist[i][0].close()
						except: pass
					lock.acquire()
					cnt += 1
					if cnt == 200:
						cnt = 0
						ts = time.time()
						newcache = {}
						for it in cache:
							if ts - cache[it][0] <= 300: newcache[it] = cache[it]
						cache = newcache
						newdnscache = {}
						for it in dnscache:
							if ts - dnscache[it][0] <= 300: newdnscache[it] = dnscache[it]
						dnscache = newdnscache
					lock.release()
		except (socket.error, ProxyException):
			print 'socket error'
			try: remote.close()
			except: pass
def handler(sig, frame):
	global config
	global cache
	config = getconf()
	lock.acquire()
	cache = {}
	dnscache = {}
	lock.release()
def main():
	signal.signal(signal.SIGHUP, handler)
	server = ThreadingTCPServer(('127.0.0.1', 1080), Socks5Server)
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		server.shutdown()
		server.server_close()

os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
config = getconf()
cache = {}
dnscache = {}
lock = threading.Lock()
cnt = 0
if __name__ == '__main__':
	main()
