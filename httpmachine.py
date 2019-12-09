import base64
from proxylib import ProxyException
CHARSET_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
CHARSET_DIGIT = '0123456789'
CHARSET_HEX = '0123456789ABCDEFabcdef'
CHARSET_PRINT = map(chr, range(32, 256))
CHARSET_ALL = map(chr, range(0, 256))
CHARSET_URL = map(chr, range(33, 127))

class HTTPMachineBase:
	STATE_INIT = 0
	STATE_HEADER = 99
	STATE_BODY = 100
	STATE_FINISH = 999
	NODE_INIT = 0
	NODE_HEADER_ENTR = 900
	NODE_NORMAL_ENTR = 1000
	NODE_CHUNKED_ENTR = 1001
	NODE_CHUNKED_FINISH = 1006
	def _buf_shift(self, ch):
		self.buf += ch
	def _headerkey_accept(self, ch):
		self.headerkey = self.buf
		self.buf = ''
	def _headerval_accept(self, ch):
		self.header.append((self.headerkey, self.buf))
		self.headerkeys.append(self.headerkey.lower())
		self.buf = ''
	def _header_accept(self, ch):
		if self._body_needed():
			self.state = HTTPMachineBase.STATE_BODY
			if self._body_chunked():
				self.node = HTTPMachineBase.NODE_CHUNKED_ENTR
				self.buf = ''
			else:
				self.bodylen = self._body_length()
				if self.bodylen == 0:
					self.state_finish()
				else:
					self.bodynum = 0
					self.node = HTTPMachineBase.NODE_NORMAL_ENTR
		else:
			self.state_finish()
	def _header_getvalue(self, key):
		key = key.lower()
		if key in self.headerkeys:
			index = self.headerkeys.index(key)
			return self.header[index][1]
		return None
	def _body_chunked(self):
		val = self._header_getvalue('transfer-encoding')
		return val is not None and val.find('chunked') != -1
	def _body_length(self):
		val = self._header_getvalue('content-length')
		return -1 if val is None else int(val)
	def _body_normal_shift(self, ch):
		self.bodynum += 1
		if self.bodynum == self.bodylen:
			self.state_finish()
	def _body_chunked_len_accept(self, ch):
		self.chunklen = int(self.buf, 16)
		self.chunknum = 0
		self.buf = ''
	def _body_chunked_chunk_shift(self, ch):
		self.chunknum += 1
		if self.chunknum == self.chunklen:
			self.node = HTTPMachineBase.NODE_CHUNKED_FINISH
	def _body_chunked_trailer_accept(self, ch):
		self.state_finish()
	def _make_trans(self):
		self.trans = {
				900: ([(CHARSET_ALPHA + CHARSET_DIGIT + '-_', 901), ('\r', 905)], None),
				901: ([(CHARSET_ALPHA + CHARSET_DIGIT + '-_', 901), (':', 902)], self._buf_shift),
				902: ([(CHARSET_PRINT, 903), ('\r', 904)], self._headerkey_accept),
				903: ([(CHARSET_PRINT, 903), ('\r', 904)], self._buf_shift),
				904: ([('\n', 900)], self._headerval_accept),
				905: ([('\n', 906)], None),
				906: ([], self._header_accept),
				1000: ([(CHARSET_ALL, 1000)], self._body_normal_shift),
				1001: ([('0', 1008), (CHARSET_HEX, 1002)], None),
				1002: ([(CHARSET_HEX, 1002), ('\r', 1003)], self._buf_shift),
				1003: ([('\n', 1004)], None),
				1004: ([(CHARSET_ALL, 1005)], self._body_chunked_len_accept),
				1005: ([(CHARSET_ALL, 1005)], self._body_chunked_chunk_shift),
				1006: ([('\r', 1007)], None),
				1007: ([('\n', 1001)], None),
				1008: ([(CHARSET_HEX, 1002), ('\r', 1009)], self._buf_shift),
				1009: ([('\n', 1010)], self._body_chunked_len_accept),
				1010: ([(CHARSET_ALPHA + CHARSET_DIGIT + '-_', 1011), ('\r', 1015)], None),
				1011: ([(CHARSET_ALPHA + CHARSET_DIGIT + '-_', 1011), (':', 1012)], self._buf_shift),
				1012: ([(CHARSET_PRINT, 1013), ('\r', 1014)], self._headerkey_accept),
				1013: ([(CHARSET_PRINT, 1013), ('\r', 1014)], self._buf_shift),
				1014: ([('\n', 1010)], self._headerval_accept),
				1015: ([('\n', 1016)], None),
				1016: ([], self._body_chunked_trailer_accept)
				}
	def _do_trans(self, newnode, ch):
		self.node = newnode
		func = self.trans[self.node][1]
		if func is not None: func(ch)
	def __init__(self):
		self._make_trans()
		self.state_init()
	def state_init(self):
		self.state = HTTPMachineBase.STATE_INIT
		self.node = HTTPMachineBase.NODE_INIT
		self.buf = ''
	def state_finish(self):
		self.state = HTTPMachineBase.STATE_FINISH
	def read(self, s):
		if self.state == HTTPMachineBase.STATE_FINISH:
			return 0
		cnt = 0
		for ch in s:
			cnt += 1
			flag = False
			for tr in self.trans[self.node][0]:
				if ch in tr[0]:
					self._do_trans(tr[1], ch)
					flag = True
					break
			if not flag:
				raise ValueError()
			if self.state == HTTPMachineBase.STATE_FINISH:
				return cnt
		return len(s)

class HTTPReqMachine(HTTPMachineBase):
	STATE_METHOD = 0
	STATE_URL = 1
	STATE_VERSION = 2
	def _method_accept(self, ch):
		self.state = HTTPReqMachine.STATE_URL
		self.method = self.buf
		self.buf = ''
	def _url_accept(self, ch):
		self.state = HTTPReqMachine.STATE_VERSION
		self.url = self.buf
		self.buf = ''
	def _version_accept(self, ch):
		self.state = HTTPReqMachine.STATE_HEADER
		self.version = self.buf
		self.header = []
		self.headerkeys = []
		self.buf = ''
	def _body_needed(self):
		return self.method == 'POST'
	def _make_trans(self):
		HTTPMachineBase._make_trans(self)
		self.trans.update({
			0: ([('G', 1), ('H', 2), ('P', 3), ('D', 4), ('T', 5), ('O', 6)], None),
			1: ([('E', 7)], self._buf_shift),
			2: ([('E', 8)], self._buf_shift),
			3: ([('O', 9), ('U', 7), ('A', 10)], self._buf_shift),
			4: ([('E', 11)], self._buf_shift),
			5: ([('R', 12)], self._buf_shift),
			6: ([('P', 13)], self._buf_shift),
			7: ([('T', 25)], self._buf_shift),
			8: ([('A', 14)], self._buf_shift),
			9: ([('S', 7)], self._buf_shift),
			10: ([('T', 15)], self._buf_shift),
			11: ([('L', 16)], self._buf_shift),
			12: ([('A', 17)], self._buf_shift),
			13: ([('T', 18)], self._buf_shift),
			14: ([('D', 25)], self._buf_shift),
			15: ([('C', 19)], self._buf_shift),
			16: ([('E', 20)], self._buf_shift),
			17: ([('C', 21)], self._buf_shift),
			18: ([('I', 22)], self._buf_shift),
			19: ([('H', 25)], self._buf_shift),
			20: ([('T', 21)], self._buf_shift),
			21: ([('E', 25)], self._buf_shift),
			22: ([('O', 23)], self._buf_shift),
			23: ([('N', 24)], self._buf_shift),
			24: ([('S', 25)], self._buf_shift),
			25: ([(' ', 26)], self._buf_shift),
			26: ([(CHARSET_URL, 27)], self._method_accept),
			27: ([(CHARSET_URL, 27), (' ', 28)], self._buf_shift),
			28: ([('H', 29)], self._url_accept),
			29: ([('T', 30)], self._buf_shift),
			30: ([('T', 31)], self._buf_shift),
			31: ([('P', 32)], self._buf_shift),
			32: ([('/', 33)], self._buf_shift),
			33: ([('1', 34)], self._buf_shift),
			34: ([('.', 35)], self._buf_shift),
			35: ([('01', 36)], self._buf_shift),
			36: ([('\r', 37)], self._buf_shift),
			37: ([('\n', self.NODE_HEADER_ENTR)], self._version_accept)
			})

class HTTPRespMachine(HTTPMachineBase):
	STATE_VERSION = 0
	STATE_STATUS = 1
	def _version_accept(self, ch):
		self.state = HTTPRespMachine.STATE_STATUS
		self.version = self.buf
		self.buf = ''
	def _status_accept(self, ch):
		self.state = HTTPRespMachine.STATE_HEADER
		self.status = self.buf
		self.header = []
		self.headerkeys = []
		self.buf = ''
	def _body_needed(self):
		return self.method != 'HEAD' and self.status >= '200' \
				and self.status != '204' and self.status != '304'
	def _make_trans(self):
		HTTPMachineBase._make_trans(self)
		self.trans.update({
			0: ([('H', 1)], None),
			1: ([('T', 2)], self._buf_shift),
			2: ([('T', 3)], self._buf_shift),
			3: ([('P', 4)], self._buf_shift),
			4: ([('/', 5)], self._buf_shift),
			5: ([('1', 6)], self._buf_shift),
			6: ([('.', 7)], self._buf_shift),
			7: ([('01', 8)], self._buf_shift),
			8: ([(' ', 9)], self._buf_shift),
			9: ([('012345', 10)], self._version_accept),
			10: ([(CHARSET_DIGIT, 11)], self._buf_shift),
			11: ([(CHARSET_DIGIT, 12)], self._buf_shift),
			12: ([(' ', 13), ('\r', 14)], self._buf_shift),
			13: ([(CHARSET_PRINT, 13), ('\r', 14)], None),
			14: ([('\n', self.NODE_HEADER_ENTR)], self._status_accept)
			})

class HTTPMachine:
	def _do_read_request(self, s):
		prev = self.request.state
		try: num = self.request.read(s)
		except ValueError:
			if self.reqbuf is not None:
				self.reqbuf += s
			raise
		if self.reqbuf is not None:
			self.reqbuf += s[: num]
		if prev <= HTTPReqMachine.STATE_METHOD \
				and self.request.state > HTTPReqMachine.STATE_METHOD:
			self.methods.append(self.request.method)
		if self.requrl is None \
				and self.request.state >= HTTPReqMachine.STATE_HEADER \
				and 'host' in self.request.headerkeys:
			host = val = self.request._header_getvalue('host').strip()
			port = '80'
			if host.find(':') != -1:
				host, port = host.split(':')
			self.requrl = val + self.request.url
			if 'httpaccept' in self.conf \
						and not self.conf['httpaccept'](self.requrl) \
					or 'httpexcept' in self.conf \
						and self.conf['httpexcept'](self.requrl) \
					or 'httpdomainaccept' in self.conf \
						and not self.conf['httpdomainaccept'](host, int(port)) \
					or 'httpdomainexcept' in self.conf \
						and self.conf['httpdomainexcept'](host, int(port)):
				self.reqbuf += s[num: ]
				self.request.state = HTTPMachineBase.STATE_HEADER
				raise ProxyException('HTTP filtered')
		if self.request.state >= HTTPReqMachine.STATE_BODY:
			self.reqbuf = None
		return num
	def _do_read_response(self, s):
		return self.response.read(s)
	def _new_req_machine(self):
		self.request = HTTPReqMachine()
		self.reqcnt += 1
		self.requrl = None
		self.reqbuf = ''
	def _new_resp_machine(self):
		self.response = HTTPRespMachine()
		self.respcnt += 1
	def __init__(self, conf):
		self.request = None
		self.response = None
		self.reqcnt = 0
		self.respcnt = 0
		self.reqbuf = ''
		self.methods = []
		self.conf = conf
	def req_needed(self):
		return self.request is None \
				or self.request.state != HTTPMachineBase.STATE_FINISH
	def resp_not_ready(self):
		return (self.response is None
					or self.response.state == HTTPMachineBase.STATE_FINISH) \
				and (self.respcnt == self.reqcnt or
						self.respcnt + 1 == self.reqcnt \
						and self.request.state != HTTPMachineBase.STATE_FINISH \
						and not (self.request.state == HTTPMachineBase.STATE_BODY
								and hasattr(self.request, 'bodylen')
								and self.request.bodylen == -1))
	def read_req(self, s):
		while s != '':
			num = 0
			if self.request is not None:
				num = self._do_read_request(s)
			if num < len(s):
				self._new_req_machine()
			s = s[num: ]
	def read_resp(self, s):
		while s != '':
			num = 0
			if self.response is not None:
				num = self._do_read_response(s)
			if num < len(s):
				if self.resp_not_ready():
					raise ValueError()
				self._new_resp_machine()
				self.response.method = self.methods[self.respcnt - 1]
			s = s[num: ]

class HTTPTransferMixIn:
	def _output_header_lines(self):
		for line in self.extra_header:
			self.outbuf += line[0] + ':' + line[1] + '\r\n'
		for line in self.header:
			if not line[0] in self.extra_headerkeys:
				self.outbuf += line[0] + ':' + line[1] + '\r\n'
		self.outbuf += '\r\n'
	def _do_trans(self, newnode, ch):
		self.node = newnode
		if self.state == HTTPMachineBase.STATE_BODY:
			self.outbuf += ch
		func = self.trans[self.node][1]
		if func is not None: func(ch)
	def _header_accept(self, ch):
		self._output_header()
		HTTPMachineBase._header_accept(self, ch)
	def __init__(self, conf):
		self.outbuf = ''
		self.conf = conf
		self.extra_header = []
		if 'auth' in self.conf:
			self.extra_header.append(('Proxy-Authorization',
				'Basic ' + base64.standard_b64encode(self.conf['authuser'] + ':' + self.conf['authpass'])))
		self.extra_headerkeys = map(lambda x: x[0], self.extra_header)

class HTTPReqTransferMachine(HTTPTransferMixIn, HTTPReqMachine):
	def _output_header(self):
		if self.url[: 7] != 'http://':
			requrl = 'http://' + self._header_getvalue('host').strip() + self.url
		else:
			requrl = self.url
		self.outbuf += self.method + ' ' + requrl + ' ' + self.version + '\r\n'
		self._output_header_lines()
	def __init__(self, conf):
		HTTPReqMachine.__init__(self)
		HTTPTransferMixIn.__init__(self, conf)

class HTTPRespTransferMachine(HTTPTransferMixIn, HTTPRespMachine):
	def _output_header(self):
		self.outbuf += self.version + ' ' + self.status + '\r\n'
		self._output_header_lines()
	def __init__(self, conf):
		HTTPRespMachine.__init__(self)
		HTTPTransferMixIn.__init__(self, conf)

class HTTPTransferMachine(HTTPMachine):
	def _do_read_request(self, s):
		num = HTTPMachine._do_read_request(self, s)
		self.reqoutbuf += self.request.outbuf
		self.request.outbuf = ''
		return num
	def _do_read_response(self, s):
		num = HTTPMachine._do_read_response(self, s)
		self.respoutbuf += self.response.outbuf
		self.response.outbuf = ''
		return num
	def _new_req_machine(self):
		self.request = HTTPReqTransferMachine(self.conf)
		self.reqcnt += 1
		self.requrl = None
		self.reqbuf = ''
	def _new_resp_machine(self):
		self.response = HTTPRespTransferMachine(self.conf)
		self.respcnt += 1
	def __init__(self, conf):
		HTTPMachine.__init__(self, conf)
		self.reqoutbuf = ''
		self.respoutbuf = ''
