import socket, sys, SocketServer, struct, os, time, threading, signal, getopt, proxylib
from proxylib import ProxyException
import conflib, transferer, nameresolver

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True
class Socks5Server(SocketServer.StreamRequestHandler):
	def _recv_first_msg(self):
		msg = self.connection.recvall(2)
		msg += self.connection.recvall(ord(msg[1]))
		return msg
	def _recv_second_msg(self):
		msg = self.connection.recvall(7)
		if msg[3] == '\x01':
			dlen = 3
		elif msg[3] == '\x03':
			dlen = ord(msg[4])
		elif msg[3] == '\x04':
			dlen = 15
		else:
			raise ProxyException('unknown connection type')
		msg += self.connection.recvall(dlen)
		return msg
	def handle(self):
		global config
		curconfig = config
		sock = self.connection
		try:
			print 'socks connection from ', self.client_address
			sock.settimeout(30)
			self._recv_first_msg()
			sock.sendall('\x05\x00')
			msg = self._recv_second_msg()
			mode, addrtype = ord(msg[1]), ord(msg[3])
			if addrtype == 1:
				addr = socket.inet_ntop(socket.AF_INET, msg[4: -2])
			elif addrtype == 3:
				addr = msg[5: -2]
				try:
					socket.inet_pton(socket.AF_INET, addr)
					addrtype = 1
				except: pass
				try:
					socket.inet_pton(socket.AF_INET6, addr)
					addrtype = 4
				except: pass
			elif addrtype == 4:
				addr = socket.inet_ntop(socket.AF_INET6, msg[4: -2])
			port = struct.unpack('>H', msg[-2: ])[0]
			sock.settimeout(None)
			if mode == 1:
				trans = transferer.TransfererSelector(sock,
						(addrtype, addr, port), curconfig)
				try:
					trans.setup()
					print 'Tcp connect to', addr, port
					reply = trans.transferer.replymsg()
				except ProxyException:
					trans = None
					reply = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
			else:
				trans = None
				reply = '\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00'
			sock.sendall(reply)
		except socket.error as e:
			print 'socket error'
			return
		if trans is not None:
			trans.handle_tcp()

class Timer(threading.Thread):
	def __init__(self, interval):
		threading.Thread.__init__(self)
		self.interval = interval
		self.setDaemon(True)
	def run(self):
		while True:
			time.sleep(self.interval)
			transferer._cache.cleanup()
			nameresolver._cache.cleanup()

def handler(sig, frame):
	global conffile, config
	config = conflib.getconf(conffile)
	transferer._cache.flush()
	nameresolver._cache.flush()

def main():
	global bindaddr, bindport
	try:
		signal.signal(signal.SIGHUP, handler)
	except StandardError: pass
	server = ThreadingTCPServer((bindaddr, bindport), Socks5Server)
	timer = Timer(300)
	timer.start()
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
config = conflib.getconf(conffile)
if __name__ == '__main__':
	main()
