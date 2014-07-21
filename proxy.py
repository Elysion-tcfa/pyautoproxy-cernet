import socket, sys, select, SocketServer, struct, os, time, threading, signal, getopt
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
			flag = False
			replysent = False
			try:
				if mode == 1:
					newtype = False
					lock.acquire()
					if (addr, port) in cache and time.time() - cache[(addr, port)][0] < 300:
						choice = cache[(addr, port)][1]
						lock.release()
						try:
							(remote, reply) = eval('tcp_' + choice[0]['type'])(choice[1], choice[2], port, choice[0])
							flag = True
						except (socket.error, ProxyException): pass
					else:
						lock.release()
					if not flag: newtype = True
					for conf in curconfig:
						if flag: break
						if not conf['type'] in ['direct', 'http', 'http_tunnel', 'socks4', 'socks5']: continue
						if addrtype == 3:
							if 'domainaccept' in conf and not conf['domainaccept'](addr, port): continue
							if 'domainexcept' in conf and conf['domainexcept'](addr, port): continue
						if not (addrtype == 3 and (conf['type'] in ['direct', 'socks4'] or
							(conf['type'] in ['socks5'] and 'hostname' in conf and conf['hostname'] == '0'))):
							dnsconfig = [{}]
						else:
							dnsconfig = curconfig
						resolvelist = []
						for dnsconf in dnsconfig:
							try:
								if flag: break
								if not 'type' in dnsconf:
									ip, iptype = addr, addrtype
								else:
									if not dnsconf['type'] in ['dns_direct6', 'dns_direct4', 'dns_proxy6', 'dns_proxy4']: continue
									if conf['type'] in ['socks4'] and not dnsconf['type'] in ['dns_direct4', 'dns_proxy4']: continue
									if addrtype == 3:
										if 'domainaccept' in dnsconf and not dnsconf['domainaccept'](addr, port): continue
										if 'domainexcept' in dnsconf and dnsconf['domainexcept'](addr, port): continue
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
								if not (ip, iptype) in resolvelist:
									resolvelist.append((ip, iptype))
									if iptype == 1:
										if 'ipv4accept' in conf and not conf['ipv4accept'](addr, port): continue
										if 'ipv4except' in conf and conf['ipv4except'](addr, port): continue
									elif iptype == 4:
										if 'ipv6accept' in conf and not conf['ipv6accept'](addr, port): continue
										if 'ipv6except' in conf and conf['ipv6except'](addr, port): continue
									if conf['type'] == 'http':
										if not replysent:
											sock.sendall('\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
											replysent = True
										sock.settimeout(0)
										time.sleep(0.1)
										try:
											msg = sock.recv(65536, socket.MSG_PEEK)
											header = re.match(r'(GET|HEAD|POST|PUT|DELETE|TRACE|OPTIONS|PATCH) ([^ ]*) HTTP/(1\.1|1\.0)\r\n(([A-Za-z0-9-]+: .+\r\n)*)\r\n', msg)
											if header == None:
												raise StandardError
										except:
											sock.settimeout(None)
											raise socket.error()
										sock.settimeout(None)
									(remote, reply) = eval('tcp_' + conf['type'])(ip, iptype, port, conf)
									choice = [conf, ip, iptype]
									flag = True
							except (socket.error, ProxyException): pass
					if not flag: raise ProxyException('cannot connect to host')
					if newtype:
						lock.acquire()
						cache[(addr, port)] = (time.time(), choice)
						lock.release()
					print 'Tcp connect to', addr, port
				else:
					reply = '\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00'
			except (socket.error, ProxyException):
				reply = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
			if not replysent: sock.sendall(reply)
			if flag:
				if mode == 1:
					try: handle_tcp(sock, remote, choice[0]['type'] == 'http')
					except socket.error: raise socket.error()
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
	global config, cache, dnscache, conffile
	config = getconf(conffile)
	lock.acquire()
	cache = {}
	dnscache = {}
	cnt = 0
	lock.release()
def main():
	global bindaddr, bindport
	signal.signal(signal.SIGHUP, handler)
	server = ThreadingTCPServer((bindaddr, bindport), Socks5Server)
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		server.shutdown()
		server.server_close()

bindaddr = '127.0.0.1'
bindport = 1080
conffile = os.path.join(os.path.expanduser('~'), '.pyautoproxy.conf')
for opt in getopt.getopt(sys.argv[1:], 'b:p:c:')[0]:
	if opt[0] == '-b': bindaddr = opt[1]
	elif opt[0] == '-p': bindport = int(opt[1])
	elif opt[0] == '-c': conffile = opt[1]
config = getconf(conffile)
cache = {}
dnscache = {}
lock = threading.Lock()
cnt = 0
if __name__ == '__main__':
	main()
