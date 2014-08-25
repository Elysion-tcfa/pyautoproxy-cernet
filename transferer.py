import socket, select, struct, time, base64, proxylib
from proxylib import ProxyException
import nameresolver, cache, httpmachine

class BaseTransferer:
	def __init__(self, localsock, remoteaddr, buf, conf):
		self.local = localsock
		self.addrtype, self.addr, self.port = remoteaddr
		self.conf = conf
		self.localbuf, self.remotebuf = buf
		self.timeout = 30
		if 'timeout' in conf: self.timeout = float(conf['timeout'])
	def __del__(self):
		try: self.remote.close()
		except: pass
	def setup(self):
		pass
	def replymsg(self):
		addr = self.remote.getsockname()
		if self.remote.family == socket.AF_INET6:
			msg = '\x05\x00\x00\x04' + socket.inet_pton(socket.AF_INET6, addr[0])
		else:
			msg = '\x05\x00\x00\x01' + socket.inet_pton(socket.AF_INET, addr[0])
		msg += struct.pack('>H', addr[1])
		return msg
	def finish_http_req(self, m):
		if m.reqbuf is None: raise
		while not m.resp_not_ready():
			msg = self.remote.recv(8192)
			if msg == '':
				return 0
			m.read_resp(msg)
			self.local.sendall(msg)
		self.localbuf += bytearray(m.reqbuf)
	def handle_tcp(self):
		monitor = False
		if 'httpaccept' in self.conf or 'httpexcept' in self.conf:
			monitor = True
			m = httpmachine.HTTPMachine(self.conf)
		localmsg = str(self.localbuf)
		remotemsg = str(self.remotebuf)
		self.localbuf.__init__()
		self.remotebuf.__init__()
		while True:
			if remotemsg:
				if monitor:
					try: m.read_resp(remotemsg)
					except ValueError:
						monitor = False
				self.local.sendall(remotemsg)
				remotemsg = ''
			if localmsg:
				if monitor:
					try: m.read_req(localmsg)
					except ProxyException:
						self.finish_http_req(m)
						return -1
					except ValueError:
						monitor = False
				self.remote.sendall(localmsg)
				localmsg = ''
			r, w, e = select.select([self.local, self.remote], [], [])
			if self.local in r:
				localmsg = self.local.recv(8192)
				if localmsg == '': break
			if self.remote in r:
				remotemsg = self.remote.recv(8192)
				if remotemsg == '': break
			time.sleep(0.0001)
		return 0

class DirectTransferer(BaseTransferer):
	def setup(self):
		self.remote = socket.create_connection((self.addr, self.port),
				timeout = self.timeout)
		self.remote.settimeout(None)

class Socks5Transferer(BaseTransferer):
	def setup(self):
		deadline = self.timeout + time.time()
		self.remote = socket.create_connection((self.conf['server'],
				int(self.conf['serverport'])), timeout = self.timeout)
		self.remote.sendall('\x05\x01\x00', deadline)
		msg = self.remote.recvall(2, deadline)
		if msg[1] != '\x00':
			raise ProxyException('socks5 connection failed')
		data = '\x05\x01\x00' + chr(self.addrtype)
		if self.addrtype == 1: data += socket.inet_pton(socket.AF_INET, self.addr)
		elif self.addrtype == 3: data += chr(len(self.addr)) + self.addr
		else: data += socket.inet_pton(socket.AF_INET6, self.addr)
		data += struct.pack('>H', self.port)
		self.remote.sendall(data, deadline)
		msg = self.remote.recvall(10, deadline)
		if msg[1] != '\x00':
			raise ProxyException('socks5 connection failed')
		if msg[3] == '\x04':
			self.remote.recvall(12, deadline)

class Socks4Transferer(BaseTransferer):
	def setup(self):
		if self.addrtype != 1:
			raise ProxyException('addrtype not supported by this method')
		deadline = self.timeout + time.time()
		self.remote = socket.create_connection((self.conf['server'],
				int(self.conf['serverport'])), timeout = self.timeout)
		msg = '\x04\x01' + struct.pack('>H', port) + socket.inet_pton(socket.AF_INET, addr) + '\x00'
		self.remote.sendall(msg, deadline)
		msg = self.remote.recvall(8, deadline)
		if msg[1] != 'Z':
			raise ProxyException('socks4 connection failed')

class HTTPTunnelTransferer(BaseTransferer):
	def setup(self):
		deadline = self.timeout + time.time()
		self.remote = socket.create_connection((self.conf['server'],
				int(self.conf['serverport'])), timeout = self.timeout)
		addr = self.addr
		if self.addrtype == 4:
			addr = '[' + addr + ']'
		msg = 'CONNECT ' + addr + ':' + str(self.port) + ' HTTP/1.1\r\n'
		if 'auth' in self.conf:
			msg += 'Proxy-Authorization: Basic ' + \
					base64.standard_b64encode(self.conf['authuser'] + ':' + self.conf['authpass']) + \
					'\r\n'
		msg += '\r\n'
		self.remote.sendall(msg, deadline)
		tmp = self.remote.recvuntil('\r\n\r\n', deadline)
		tmp = tmp.split()
		if len(tmp) < 2 or tmp[1] != '200':
			raise ProxyException('http tunnel connection failed')

class HTTPTransferer(BaseTransferer):
	def setup(self):
		self.wait_timeout = 3
		if 'wait_timeout' in self.conf:
			self.wait_timeout = float(self.conf['wait_timeout'])
		self.remote = socket.create_connection((self.conf['server'],
				int(self.conf['serverport'])), timeout = self.timeout)
	def handle_tcp(self):
		m = httpmachine.HTTPTransferMachine(self.conf)
		localmsg = str(self.localbuf)
		remotemsg = str(self.remotebuf)
		self.localbuf.__init__()
		self.remotebuf.__init__()
		while True:
			if remotemsg:
				m.read_resp(remotemsg)
				self.local.sendall(m.respoutbuf)
				m.respoutbuf = ''
				remotemsg = ''
			if localmsg:
				try:
					m.read_req(localmsg)
					self.remote.sendall(m.reqoutbuf)
					m.reqoutbuf = ''
					localmsg = ''
				except (ProxyException, ValueError):
					self.finish_http_req(m)
					return -1
			if m.req_needed():
				r, w, e = select.select([self.local, self.remote], [], [], self.wait_timeout)
			else:
				r, w, e = select.select([self.local, self.remote], [], [])
			if not r:
				self.finish_http_req(m)
				return -1
			if self.local in r:
				localmsg = self.local.recv(8192)
				if localmsg == '': break
			if self.remote in r:
				remotemsg = self.remote.recv(8192)
				if remotemsg == '': break
			time.sleep(0.0001)
		return 0

_cache = cache.Cache()
_classdict = {'direct': DirectTransferer, 'socks5': Socks5Transferer,
		'socks4': Socks4Transferer, 'http_tunnel': HTTPTunnelTransferer,
		'http': HTTPTransferer}

def _need_resolve(serverconf):
	return serverconf['type'] in ['direct', 'socks4'] \
			or (serverconf['type'] in ['socks5'] \
				and 'hostname' in serverconf \
				and serverconf['hostname'] == '0')

def _domain_filtered(addr, port, conf):
	return 'domainaccept' in conf and not conf['domainaccept'](addr, port) \
			or 'domainexcept' in conf and conf['domainexcept'](addr, port)

def _ipv4_filtered(addr, port, conf):
	return 'ipv4accept' in conf and not conf['ipv4accept'](addr, port) \
			or 'ipv4except' in conf and conf['ipv4except'](addr, port)

def _ipv6_filtered(addr, port, conf):
	return 'ipv6accept' in conf and not conf['ipv6accept'](addr, port) \
			or 'ipv6except' in conf and conf['ipv6except'](addr, port)

class TransfererSelector:
	def __init__(self, localsock, remoteaddr, conf):
		self.lifetime = 30.
		if 'lifetime' in conf:
			self.lifetime = float(conf['lifetime'])
		self.localsock = localsock
		self.remoteaddr = remoteaddr
		self.remoteips = None
		self.localbuf, self.remotebuf = bytearray(), bytearray()
		self.conf = conf
		self.itercount = 0
		self.iterlen = len(self.conf['servers'])
		index = _cache.lookup(self.remoteaddr)
		if index is None:
			index = 0
			self.itercount += 1
			self.iterlen += 1
		self.iterindex = index
	def setup(self):
		buf = (self.localbuf, self.remotebuf)
		addrtype, addr, port = self.remoteaddr
		deadline = time.time() + self.lifetime
		while self.itercount < self.iterlen:
			index = self.iterindex
			serverconf = self.conf['servers'][index]
			self.iterindex = (index + 1) % self.iterlen
			self.itercount += 1
			remoteaddrs = [(self.remoteaddr[0], self.remoteaddr[1])]
			if addrtype == 3:
				if _domain_filtered(addr, port, serverconf):
					continue
				if _need_resolve(serverconf):
					if self.remoteips is None:
						try:
							resolver = nameresolver.NameResolverSelector(addr, self.conf)
							self.remoteips = resolver.resolve()
						except ProxyException:
							self.remoteips = 'fail'
					if self.remoteips == 'fail':
						continue
					remoteaddrs = self.remoteips
			for addrtype2, addr2 in remoteaddrs:
				if addrtype2 == 4 and addr2[0: 7] == '::ffff:':
					try:
						socket.inet_pton(socket.AF_INET, addr2[7: ])
						addr2 = addr2[7: ]
						addrtype2 = 1
					except socket.error: pass
				if addrtype2 == 1 and _ipv4_filtered(addr2, port, serverconf) \
						or addrtype2 == 4 and _ipv6_filtered(addr2, port, serverconf):
					continue
				self.transferer = _classdict[serverconf['type']](
						self.localsock, (addrtype2, addr2, port), buf, serverconf)
				self.transferer.timeout = min(self.transferer.timeout,
						deadline - time.time())
				try:
					self.transferer.setup()
				except: continue
				self.lifetime = deadline - time.time()
				if self.itercount > 1:
					_cache.insert(self.remoteaddr, index)
				return
		raise ProxyException('cannot connect to host')
	def handle_tcp(self):
		while True:
			ret = self.transferer.handle_tcp()
			if ret == 0: break
			self.setup()
