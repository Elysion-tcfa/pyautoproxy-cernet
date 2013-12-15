import sys, socket, ctypes, select, struct, time, re, conflib
windows = (sys.platform.startswith('win32') or sys.platform.startswith('cygwin'))
if windows:
	winsock = ctypes.WinDLL("ws2_32.dll")

class ProxyException(Exception):
	def __init__(self, value = ''):
		self.value = value
	def __str__(self):
		return repr(self.value)

def inet_pton(af, ip):
	if windows:
		if af == socket.AF_INET: return socket.inet_aton(ip)
		else:
			res = 'sakura~anatanideaeteyokatta'
			if not winsock.inet_pton(af, ip, res): raise socket.error('illegal ip address')
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
def gethostbyname(af, addr, conf):
	return socket.getaddrinfo(addr, 0, af, socket.SOCK_STREAM, socket.SOL_TCP)[0][4][0]
def gethostbyname_extra(af, addr, conf):
	try:
		inet_pton(af, addr)
		return addr
	except socket.error: pass
	try:
		inet_pton(socket.AF_INET6, conf['server'])
		sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
	except socket.error:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	if af == socket.AF_INET6:
		ch = '\x1c'
	else:
		ch = '\x01'
	msg = '\x05\x16\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
	msg += reduce(lambda x, y: x + chr(len(y)) + y, ('.' + addr).split('.'))
	msg += '\x00\x00' + ch + '\x00\x01'
	msgr = None
	for i in range(0, int(conf['attempt'])):
		if 'serverport' in conf:
			sock.sendto(msg, (conf['server'], int(conf['serverport'])))
		else:
			sock.sendto(msg, (conf['server'], 53))
		if select.select([sock], [], [], int(conf['timeout']))[0]:
			msgr = sock.recv(65536)
			break
	sock.close()
	if msgr == None: raise socket.error('cannot connect to dns server')
	if ord(msgr[3]) % 16 != 0: raise socket.error('cannot get host')
	num = struct.unpack('>H', msgr[6: 8])[0]
	msgr = msgr[len(msg): ]
	while num > 0:
		pos = msgr.find('\x00')
		if msgr[pos + 1] == ch:
			if af == socket.AF_INET6:
				return inet_ntop(af, msgr[pos + 10: pos + 26])
			else:
				return inet_ntop(af, msgr[pos + 10: pos + 14])
		else:
			msgr = msgr[pos + 10 + ord(msgr[pos + 9]): ]
		num -= 1
	raise socket.error('cannot get host')
def recvall(sock, count):
	data = ''
	while len(data) < count:
		d = sock.recv(count - len(data))
		if not d: raise socket.error('connection closed unexpectedly')
		data = data + d
	return data
def reply(af, remote):
	local = remote.getsockname()
	if af == socket.AF_INET6:
		return '\x05\x00\x00\x04' + inet_pton(socket.AF_INET6, local[0]) + struct.pack('>H', local[1])
	else:
		return '\x05\x00\x00\x01' + inet_pton(socket.AF_INET, local[0]) + struct.pack('>H', local[1])

def tcp_connect(addr, port, conf):
	try:
		af = socket.AF_INET
		inet_pton(af, addr)
	except socket.error:
		af = socket.AF_INET6
	remote = socket.socket(af, socket.SOCK_STREAM)
	try:
		remote.settimeout(int(conf['timeout']))
	except StandardError: pass
	remote.connect((addr, port))
	remote.settimeout(None)
	return (af, remote)
def handle_tcp(sock, remotelist):
	httpmode = False
	remoteid = 0
	for i in range(0, len(remotelist)):
		if remotelist[i][1]['type'] == 'http':
			remoteid = i
			httpmode = True
			nowclient = True
			contentlen = -1
			break
	while True:
		r, w, e = select.select([sock, remotelist[remoteid][0]], [], [])
		if sock in r:
			msg = sock.recv(8192)
			if len(msg) == 0: break
			if httpmode:
				try:
					if not nowclient: raise ProxyException()
					if contentlen == -1:
						header = re.match(r'(GET|HEAD|POST|PUT|DELETE|TRACE|OPTIONS|PATCH) ([^ ]*) HTTP/(1\.1|1\.0|0\.9)\r\n(([A-Za-z0-9-]+: .+\r\n)*)\r\n', msg)
						if header == None: raise ProxyException()
						body = msg[len(header.group(0)): ]
						header = header.groups()
						headerdict = {}
						for it in re.finditer(r'([A-Za-z0-9-]+): (.+)\r\n', header[3]):
							headerdict[it.group(1)] = it.group(2)
						if 'Host' not in headerdict: raise ProxyException()
						if 'Content-Length' in headerdict:
							contentlen = int(headerdict['Content-Length'])
						else:
							contentlen = 0
						msg = '%s http://%s%s HTTP/%s\r\n%s\r\n%s' % (header[0], headerdict['Host'], header[1], header[2], header[3], body)
					else:
						body = msg
					contentlen -= len(body)
					if contentlen <= 0:
						nowclient = False
						contentlen = -1
				except ProxyException:
					remotelist[remoteid][0].close()
					httpmode = False
					remoteid = -1
					for i in range(0, len(remotelist)):
						if remotelist[i][1]['type'] != 'http':
							remoteid = i
							break
					if remoteid == -1: break
			time.sleep(0.0001)
			if remotelist[remoteid][0].sendall(msg) != None: break
		if remotelist[remoteid][0] in r:
			msg = remotelist[remoteid][0].recv(8192)
			if len(msg) == 0: break
			if httpmode:
				try:
					if nowclient: raise ProxyException()
					if contentlen == -1:
						header = re.match(r'HTTP/(1\.1|1\.0|0\.9) \d{3}( [A-Za-z0-9-]*)?\r\n(([A-Za-z0-9-]+: .+\r\n)*)\r\n', msg)
						if header == None: raise ProxyException()
						body = msg[len(header.group(0)): ]
						header = header.groups()
						headerdict = {}
						for it in re.finditer(r'([A-Za-z0-9-]+): (.+)\r\n', header[2]):
							headerdict[it.group(1)] = it.group(2)
						if 'Content-Length' in headerdict:
							contentlen = int(headerdict['Content-Length'])
						else:
							contentlen = 0
					else:
						body = msg
					contentlen -= len(body)
					if contentlen <= 0:
						nowclient = True
						contentlen = -1
				except ProxyException:
					httpmode = False
					remoteid = -1
					for i in range(0, len(remotelist)):
						if remotelist[i][1]['type'] != 'http':
							remoteid = i
							break
					if remoteid == -1: break
			time.sleep(0.0001)
			if sock.sendall(msg) != None: break

def tcp_direct(addr, addrtype, port, conf):
	(af, remote) = tcp_connect(addr, port, conf)
	return (remote, reply(af, remote))
def tcp_socks5(addr, addrtype, port, conf):
	(af, remote) = tcp_connect(conf['server'], int(conf['serverport']), conf)
	remote.sendall('\x05\x01\x00')
	if recvall(remote, 2)[1] != '\x00': raise ProxyException('socks5 connection failed')
	data = '\x05\x01\x00' + chr(addrtype)
	if addrtype == 1: data += inet_pton(socket.AF_INET, addr)
	elif addrtype == 3: data += chr(len(addr)) + addr
	else: data += inet_pton(socket.AF_INET6, addr)
	data += struct.pack('>H', port)
	remote.sendall(data)
	msg = remote.recv(4096)
	if len(msg) < 2 or msg[1] != '\x00': raise ProxyException('socks5 connection failed')
	return (remote, reply(af, remote))
def tcp_socks4(addr, addrtype, port, conf):
	if addrtype != 1: raise ProxyException('addrtype not supported by this method')
	(af, remote) = tcp_connect(conf['server'], int(conf['serverport']), conf)
	remote.sendall('\x04\x01' + struct.pack('>H', port) + inet_pton(socket.AF_INET, addr) + 'vani\x00')
	msg = recvall(remote, 8)
	if len(msg) < 2 or msg[1] != 'Z': raise ProxyException('socks4 connection failed')
	return (remote, reply(af, remote))
def tcp_http_tunnel(addr, addrtype, port, conf):
	(af, remote) = tcp_connect(conf['server'], int(conf['serverport']), conf)
	if addrtype == 4: addr = '[' + addr + ']'
	remote.sendall('CONNECT ' + addr + ':' + str(port) + ' HTTP/1.1\r\n\r\n')
	tmp = remote.recv(4096).split(' ')
	if len(tmp) < 2 or tmp[1] != '200': raise ProxyException('http tunnel connection failed')
	return (remote, reply(af, remote))
def tcp_http(addr, addrtype, port, conf):
	(af, remote) = tcp_connect(conf['server'], int(conf['serverport']), conf)
	return (remote, reply(af, remote))

def tcpdns_direct6(addr, conf):
	return (socket.AF_INET6, gethostbyname(socket.AF_INET6, addr, conf))
def tcpdns_direct4(addr, conf):
	return (socket.AF_INET, gethostbyname(socket.AF_INET, addr, conf))
def tcpdns_proxy6(addr, conf):
	try:
		return (socket.AF_INET6, gethostbyname_extra(socket.AF_INET6, addr, conf))
	except socket.error:
		raise ProxyException('dns_proxy6 failed')
def tcpdns_proxy4(addr, conf):
	try:
		return (socket.AF_INET, gethostbyname_extra(socket.AF_INET, addr, conf))
	except socket.error:
		raise ProxyException('dns_proxy4 failed')
