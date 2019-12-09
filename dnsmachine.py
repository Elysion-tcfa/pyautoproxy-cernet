import struct
from proxylib import ProxyException
CHARSET_ALL = map(chr, range(0, 256))

class DNSReqMachine:
	STATE_INIT = 0
	STATE_FINISH = 1
	def _buf_shift(self, ch):
		self.buf += ch
	def _total_len(self, ch):
		self.total_len = struct.unpack('>H', self.buf + ch)[0]
		self.buf = ''
	def _query_cnt(self, ch):
		self.query_cnt = struct.unpack('>H', self.buf + ch)[0]
		try: assert self.query_cnt > 0
		except: raise ValueError()
		self.buf = ''
	def _addition_cnt(self, ch):
		self.addition_cnt = struct.unpack('>H', self.buf + ch)[0]
		self.buf = ''
	def _section_len(self, ch):
		self.section_len = ord(ch)
		if self.section_len == 0:
			self.domains.append('.'.join(self.sections))
			self.sections = []
			self.node = 17
		else:
			self.node = 16
	def _section_shift(self, ch):
		self.buf += ch
		self.section_len -= 1
		if self.section_len == 0:
			self.sections.append(self.buf)
			self.buf = ''
			self.node = 14
	def _addition_section_len(self, ch):
		self.section_len = ord(ch)
		if self.section_len == 0:
			self.node = 25
		else:
			self.node = 24
	def _addition_section_shift(self, ch):
		self.section_len -= 1
		if self.section_len == 0:
			self.node = 22
	def _query_finish(self, ch):
		self.query_cnt -= 1
		if self.query_cnt == 0:
			if self.addition_cnt == 0:
				self.state = DNSReqMachine.STATE_FINISH
			else:
				self.node = 22
		else:
			self.node = 14
	def _addition_body_len(self, ch):
		self.section_len = struct.unpack('>H', self.buf + ch)[0]
		if self.section_len > 0:
			self.node = 36
		else:
			self.section_len = 1
			self._addition_body_shift('x')
	def _addition_body_shift(self, ch):
		self.section_len -= 1
		if self.section_len == 0:
			self.addition_cnt -= 1
			if self.addition_cnt == 0:
				self.state = DNSReqMachine.STATE_FINISH
			else:
				self.node = 22
	def _make_trans(self):
		self.trans = {
				0: ([(CHARSET_ALL, 1)], None),
				1: ([(CHARSET_ALL, 2)], self._buf_shift),
				2: ([(CHARSET_ALL, 3)], self._total_len),
				3: ([(CHARSET_ALL, 4)], None),
				4: ([('\x00\x01', 5)], None),
				5: ([(CHARSET_ALL, 6)], None),
				6: ([(CHARSET_ALL, 7)], None),
				7: ([(CHARSET_ALL, 8)], self._buf_shift),
				8: ([('\x00', 9)], self._query_cnt),
				9: ([('\x00', 10)], None),
				10: ([('\x00', 11)], None),
				11: ([('\x00', 12)], None),
				12: ([(CHARSET_ALL, 13)], None),
				13: ([(CHARSET_ALL, 14)], self._buf_shift),
				14: ([(CHARSET_ALL, 15)], self._addition_cnt),
				15: ([], self._section_len),
				16: ([(CHARSET_ALL, 16)], self._section_shift),
				17: ([(CHARSET_ALL, 18)], None),
				18: ([(CHARSET_ALL, 19)], None),
				19: ([(CHARSET_ALL, 20)], None),
				20: ([(CHARSET_ALL, 21)], None),
				21: ([], self._query_finish),
				22: ([(CHARSET_ALL, 23)], None),
				23: ([], self._addition_section_len),
				24: ([(CHARSET_ALL, 24)], self._addition_section_shift),
				25: ([(CHARSET_ALL, 26)], None),
				26: ([(CHARSET_ALL, 27)], None),
				27: ([(CHARSET_ALL, 28)], None),
				28: ([(CHARSET_ALL, 29)], None),
				29: ([(CHARSET_ALL, 30)], None),
				30: ([(CHARSET_ALL, 31)], None),
				31: ([(CHARSET_ALL, 32)], None),
				32: ([(CHARSET_ALL, 33)], None),
				33: ([(CHARSET_ALL, 34)], None),
				34: ([(CHARSET_ALL, 35)], self._buf_shift),
				35: ([], self._addition_body_len),
				36: ([(CHARSET_ALL, 36)], self._addition_body_shift)
				}
	def _do_trans(self, newnode, ch):
		self.node = newnode
		func = self.trans[self.node][1]
		if func is not None: func(ch)
	def __init__(self):
		self._make_trans()
		self.state_init()
	def state_init(self):
		self.state = DNSReqMachine.STATE_INIT
		self.node = 0
		self.total_len = -1
		self.buf = ''
		self.sections = []
		self.domains = []
	def read(self, s):
		if self.state == DNSReqMachine.STATE_FINISH:
			return 0
		cnt = 0
		for ch in s:
			cnt += 1
			if self.total_len >= 0:
				self.total_len -= 1
				if self.total_len < 0:
					raise ValueError()
			flag = False
			for tr in self.trans[self.node][0]:
				if ch in tr[0]:
					self._do_trans(tr[1], ch)
					flag = True
					break
			if not flag:
				raise ValueError()
			if self.state == DNSReqMachine.STATE_FINISH:
				if self.total_len > 0:
					raise ValueError()
				return cnt
		return len(s)

class DNSRespMachine:
	STATE_INIT = 0
	STATE_FINISH = 1
	def _buf_shift(self, ch):
		self.buf += ch
	def _total_len(self, ch):
		self.total_len = struct.unpack('>H', self.buf + ch)[0]
		self.buf = ''
		self.node = 3
	def _body_shift(self, ch):
		self.buf += ch
		self.total_len -= 1
		if self.total_len == 0:
			self.state = DNSRespMachine.STATE_FINISH
	def _make_trans(self):
		self.trans = {
				0: ([(CHARSET_ALL, 1)], None),
				1: ([(CHARSET_ALL, 2)], self._buf_shift),
				2: ([], self._total_len),
				3: ([(CHARSET_ALL, 3)], self._body_shift)
				}
	def _do_trans(self, newnode, ch):
		self.node = newnode
		func = self.trans[self.node][1]
		if func is not None: func(ch)
	def __init__(self):
		self._make_trans()
		self.state_init()
	def state_init(self):
		self.state = DNSRespMachine.STATE_INIT
		self.node = 0
		self.buf = ''
	def read(self, s):
		if self.state == DNSRespMachine.STATE_FINISH:
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
			if self.state == DNSRespMachine.STATE_FINISH:
				return cnt
		return len(s)

class DNSMachine:
	def _do_read_request(self, s):
		try: num = self.request.read(s)
		except ValueError:
			if self.reqbuf is not None:
				self.reqbuf += s
			raise
		if self.reqbuf is not None:
			self.reqbuf += s[: num]
		if self.request.state == DNSReqMachine.STATE_FINISH:
			for domain in self.request.domains:
				if 'dnsaccept' in self.conf \
							and not self.conf['dnsaccept'](domain, 0) \
						or 'dnsexcept' in self.conf \
							and self.conf['dnsexcept'](domain, 0):
					self.reqbuf += s[num: ]
					print domain, 'filtered'
					self.request.state = DNSReqMachine.STATE_INIT
					raise ProxyException('DNS filtered')
			self.reqbuf = None
		else:
			print repr(s), self.request.state
		return num
	def _do_read_response(self, s):
		return self.response.read(s)
	def _new_req_machine(self):
		self.request = DNSReqMachine()
		self.reqcnt += 1
	def _new_resp_machine(self):
		self.response = DNSRespMachine()
		self.respcnt += 1
	def __init__(self, conf):
		self.request = None
		self.response = None
		self.reqcnt = 0
		self.respcnt = 0
		self.reqbuf = ''
		self.conf = conf
	def resp_not_ready(self):
		return (self.response is None
					or self.response.state == DNSRespMachine.STATE_FINISH) \
				and (self.respcnt == self.reqcnt or
						self.respcnt + 1 == self.reqcnt \
						and self.request.state != DNSReqMachine.STATE_FINISH)
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
			s = s[num: ]
