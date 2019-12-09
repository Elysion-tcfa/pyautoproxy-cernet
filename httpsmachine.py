import struct, re
from proxylib import ProxyException
CHARSET_ALL = map(chr, range(0, 256))

class HTTPSReqMachine:
	STATE_INIT = 0
	STATE_FINISH = 1
	def _buf_shift(self, ch):
		self.buf += ch
	def _append_total_len(self, ch):
		self.lengths.append(struct.unpack('>H', self.buf + ch)[0])
		self.buf = ''
	def _append_msg_len(self, ch):
		self.lengths.append(struct.unpack('>I', '\x00' + self.buf + ch)[0])
		self.buf = ''
	def _one_byte_len(self, next_node):
		def func(ch):
			self.pending_len = ord(ch)
			self.node = next_node
		return func
	def _two_byte_len(self, next_node):
		def func(ch):
			self.pending_len = struct.unpack('>H', self.buf + ch)[0]
			self.buf = ''
			self.node = next_node
		return func
	def _len_shift(self, next_node):
		def func(ch):
			self.pending_len -= 1
			if self.pending_len <= 0:
				self.node = next_node
		return func
	def _random_len(self, ch):
		self.pending_len = 32
		self.node = 12
	def _session_len(self, ch):
		self._one_byte_len(15)(ch)
		if self.pending_len > 32:
			raise ValueError()
	def _cipher_len(self, ch):
		self._two_byte_len(19)(ch)
		if self.pending_len % 2 != 0:
			raise ValueError()
	def _extension_val(self, ch):
		self.buf += ch
		if len(self.buf) >= self.pending_len:
			for length in self.lengths:
				if length > 0:
					raise ValueError()
			self.state = HTTPSReqMachine.STATE_FINISH
			self.extension = self.buf
	def _make_trans(self):
		self.trans = {
				0: ([('\x16', 1)], None),
				1: ([('\x03', 2)], None),
				2: ([('\x01\x02\x03', 3)], None),
				3: ([(CHARSET_ALL, 4)], None),
				4: ([(CHARSET_ALL, 5)], self._buf_shift),
				5: ([('\x01', 6)], self._append_total_len),
				6: ([(CHARSET_ALL, 7)], None),
				7: ([(CHARSET_ALL, 8)], self._buf_shift),
				8: ([(CHARSET_ALL, 9)], self._buf_shift),
				9: ([('\x03', 10)], self._append_msg_len),
				10: ([('\x01\x02\x03', 11)], None),
				11: ([], self._random_len),
				12: ([(CHARSET_ALL, 12)], self._len_shift(13)),
				13: ([(CHARSET_ALL, 14)], None),
				14: ([], self._session_len),
				15: ([(CHARSET_ALL, 15)], self._len_shift(16)),
				16: ([(CHARSET_ALL, 17)], None),
				17: ([(CHARSET_ALL, 18)], self._buf_shift),
				18: ([], self._cipher_len),
				19: ([(CHARSET_ALL, 19)], self._len_shift(20)),
				20: ([(CHARSET_ALL, 21)], None),
				21: ([], self._one_byte_len(22)),
				22: ([(CHARSET_ALL, 22)], self._len_shift(23)),
				23: ([(CHARSET_ALL, 24)], None),
				24: ([(CHARSET_ALL, 25)], self._buf_shift),
				25: ([], self._two_byte_len(26)),
				26: ([(CHARSET_ALL, 26)], self._extension_val)
				}
	def _do_trans(self, newnode, ch):
		self.node = newnode
		func = self.trans[self.node][1]
		if func is not None: func(ch)
	def __init__(self):
		self._make_trans()
		self.state_init()
	def state_init(self):
		self.state = HTTPSReqMachine.STATE_INIT
		self.node = 0
		self.buf = ''
		self.lengths = []
	def read(self, s):
		if self.state == HTTPSReqMachine.STATE_FINISH:
			return 0
		cnt = 0
		for ch in s:
			cnt += 1
			for i in range(0, len(self.lengths)):
				self.lengths[i] -= 1
				if self.lengths[i] < 0:
					raise ValueError()
			flag = False
			for tr in self.trans[self.node][0]:
				if ch in tr[0]:
					self._do_trans(tr[1], ch)
					flag = True
					break
			if not flag:
				raise ValueError()
			if self.state == HTTPSReqMachine.STATE_FINISH:
				return cnt
		return len(s)

class HTTPSMachine:
	def _do_read_request(self, s):
		try: num = self.request.read(s)
		except ValueError:
			if self.reqbuf is not None:
				self.reqbuf += s
			raise
		if self.reqbuf is not None:
			self.reqbuf += s[: num]
		if self.request.state == HTTPSReqMachine.STATE_FINISH:
			for match in re.finditer(r'[\x00-\xff]{7}[a-z0-9-]+(\.[a-z0-9-]+)+', self.request.extension):
				msg = match.group(0)
				expected_len1 = struct.unpack('>H', msg[0:2])[0]
				expected_len2 = struct.unpack('>H', msg[2:4])[0]
				expected_len3 = struct.unpack('>I', '\x00' + msg[4:7])[0]
				if len(msg) != 2 + expected_len1 or expected_len1 != 2 + expected_len2 or expected_len2 != 3 + expected_len3:
					continue
				domain = msg[7:]
				if 'httpsaccept' in self.conf \
							and not self.conf['httpsaccept'](domain, 0) \
						or 'httpsexcept' in self.conf \
							and self.conf['httpsexcept'](domain, 0):
					self.reqbuf += s[num: ]
					raise ProxyException('HTTPS filtered')
			self.reqbuf = None
		return num
	def __init__(self, conf):
		self.request = HTTPSReqMachine()
		self.reqbuf = ''
		self.conf = conf
	def resp_not_ready(self):
		return True
	def read_req(self, s):
		while s != '':
			num = 0
			if self.request is not None:
				if self.request.state != HTTPSReqMachine.STATE_FINISH:
					num = self._do_read_request(s)
				else:
					num = len(s)
			s = s[num: ]
	def read_resp(self, s):
		pass
