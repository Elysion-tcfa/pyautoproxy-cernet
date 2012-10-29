import socket, select, sys, struct
def parsedns(domain, flag1, server, flag2):
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
	for i in range(0, 5):
		sock.sendto(msg, (server, 53))
		if select.select([sock], [], [], 5)[0]:
			msgr = sock.recv(65536)
			break
	sock.close()
	if msgr == None:
		sys.stderr.write('cannot connect to dns server\n')
		return None
	if ord(msgr[3]) % 16 != 0:
		sys.stderr.write('cannot get host\n')
		return None
	num = struct.unpack('>H', msgr[6: 8])[0]
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
	sys.stderr.write('cannot get host\n')
	return None
print parsedns("www.host1free.com", False, "2001:778::37", True)
