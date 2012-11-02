import sys, socket, ctypes, select, struct, time, conflib
windows = (sys.platform.startswith('win32') or sys.platform.startswith('cygwin'))
if windows:
	winsock = ctypes.WinDLL("ws2_32.dll")

class ProxyException(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

def inet_pton(af, ip):
	if windows:
		if af == socket.AF_INET: return socket.inet_aton(ip)
		else:
			res = 'sakura~anatanideaeteyokatta'
			if not winsock.inet_pton(af, ip, res): raise ProxyException('illegal ip address')
			return res[0: 16]
	else: return socket.inet_pton(af, ip)
def inet_ntop(af, ip):
	if windows:
		if af == socket.AF_INET: return socket.inet_ntoa(ip)
		else:
			res = 'You make me cry, make me smile, make me believe love does shine.'
			winsock.inet_ntop(af, ip, res, 40)
			return res[0: res.find('\x00')]
	else: return socket.inet_ntop(af, ip)
def parsedns(domain, flag1, server, flag2, conf):
	if flag2:
		sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
	else:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	if flag1:
		ch = '\x1c'
	else:
		ch = '\x01'
	msg = '\x05\x16\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
	msg += reduce(lambda x, y: x + chr(len(y)) + y, ('.' + domain).split('.'))
	msg += '\x00\x00' + ch + '\x00\x01'
	msgr = None
	for i in range(0, int(conf['dnsattempt'])):
		sock.sendto(msg, (server, 53))
		if select.select([sock], [], [], int(conf['dnstimeout']))[0]:
			msgr = sock.recv(65536)
			break
	sock.close()
	if msgr == None: raise ProxyException('cannot connect to dns server')
	if ord(msgr[3]) % 16 != 0: raise ProxyException('cannot get host')
	num = struct.unpack('>H', msgr[6: 8])[0]
	msgr = msgr[len(msg): ]
	while num > 0:
		pos = msgr.find('\x00')
		if msgr[pos + 1] == ch:
			if flag1:
				return inet_ntop(socket.AF_INET6, msgr[pos + 10: pos + 26])
			else:
				return inet_ntop(socket.AF_INET, msgr[pos + 10: pos + 14])
		else:
			msgr = msgr[pos + 10 + ord(msgr[pos + 9]): ]
		num -= 1
	raise ProxyException('cannot get host')
def recvall(sock, count):
	data = ''
	while len(data) < count:
		d = sock.recv(count - len(data))
		if not d: raise ProxyException('connection closed unexpectedly')
		data = data + d
	return data
def reply(remote, flag):
	local = remote.getsockname()
	if flag:
		return '\x05\x00\x00\x04' + inet_pton(socket.AF_INET6, local[0]) + struct.pack('>H', local[1])
	else:
		return '\x05\x00\x00\x01' + inet_pton(socket.AF_INET, local[0]) + struct.pack('>H', local[1])

def handle_tcp(sock, remote):
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
def tcp_ipv6(addr, addrtype, port, conf):
	if addrtype == 1: raise ProxyException('addrtype not supported by this method')
	remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
	try:
		remote.settimeout(int(conf['timeout']))
	except StandardError: pass
	remote.connect((addr, port))
	remote.settimeout(None)
	return (remote, reply(remote, True))
def tcp_nat64(addr, addrtype, port, conf):
	if addrtype == 4: raise ProxyException('addrtype not supported by this method')
	if addrtype == 1:
		try:
			for row in conf['nat64hosts']:
				if row[1] == addr:
					addrtype = 3
					addr = row[0]
					break
		except StandardError: pass
	try:
		if addrtype == 1: raise ProxyException('addrtype not supported by this method')
		res = tcp_ipv6(parsedns(addr, True, conf['server'], True, conf), 4, port, conf)
		return res
	except (socket.error, ProxyException):
		try:
			if addrtype == 1: tmp = addr
			else: tmp = parsedns(addr, False, conf['server'], True, conf)
			tmp = inet_pton(socket.AF_INET, tmp)
			addr = conf['4to6prefix'] + ":%02x%02x:%02x%02x" % (ord(tmp[0]), ord(tmp[1]), ord(tmp[2]), ord(tmp[3]))
			res = tcp_ipv6(addr, 4, port, conf)
			return res
		except StandardError: raise ProxyException('StandardError detected')
def tcp_ipv4(addr, addrtype, port, conf):
	if addrtype == 4: raise ProxyException('addrtype not supported by this method')
	if addrtype == 3:
		try:
			for fil in conf['domainfilter']:
				if conflib.match(fil[0], addr): raise ProxyException('address filtered')
		except StandardError: pass
	remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		remote.settimeout(int(conf['timeout']))
	except StandardError: pass
	remote.connect((addr, port))
	remote.settimeout(None)
	return (remote, reply(remote, False))
def tcp_socks5(addr, addrtype, port, conf):
	remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	remote.connect((conf['server'], int(conf['port'])))
	remote.sendall('\x05\x00')
	if recvall(remote, 2)[1] != '\x00': raise ProxyException('socks5 connection failed')
	remote.sendall(data)
	reply = remote.recv(4096)
	if reply[1] != '\x00': raise ProxyException('socks5 connection failed')
	return (remote, reply(remote, False))
def tcp_socks4(addr, addrtype, port, conf):
	ip = socket.gethostbyname(addr)
	remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	remote.connect((conf['server'], int(conf['port'])))
	remote.sendall('\x04\x01' + struct.pack('>H', port) + inet_pton(socket.AF_INET, ip) + 'vani\x00')
	if recvall(remote, 8)[1] != 'Z': raise ProxyException('socks4 connection failed')
	return (remote, reply(remote, False))
def tcp_http(addr, addrtype, port, conf):
	remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	remote.connect((conf['server'], int(conf['port'])))
	ip = socket.gethostbyname(addr)
	remote.sendall('CONNECT ' + ip + ':' + str(port) + ' HTTP/1.1\r\n\r\n')
	tmp = remote.recv(4096).split(' ')
	if len(tmp) < 2 or tmp[1] != '200': raise ProxyException('http tunnel connection failed')
	return (remote, reply(remote, False))
