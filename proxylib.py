import sys, socket, ctypes, select, struct, time, re
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
def sendall(sock, msg, deadline = None):
	while msg:
		if deadline is not None:
			sock.settimeout(deadline - time.time())
		l = sock.send(msg)
		msg = msg[l: ]
	sock.settimeout(None)
def recvall(sock, count, deadline = None):
	data = ''
	while len(data) < count:
		if deadline is not None:
			sock.settimeout(deadline - time.time())
		d = sock.recv(count - len(data))
		if not d: raise socket.error('connection closed unexpectedly')
		data += d
	sock.settimeout(None)
	return data
def recvuntil(sock, ending, deadline = -1):
	data = ''
	while True:
		if deadline is not None:
			sock.settimeout(deadline - time.time())
		d = sock.recv(1)
		if not d: raise socket.error('connection closed unexpectedly')
		data += d
		if data[-len(ending): ] == ending: break
	sock.settimeout(None)
	return data
