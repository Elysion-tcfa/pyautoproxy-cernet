import re, socket, struct
from proxylib import inet_pton

def gettable(fpath):
	fp = open(fpath, 'rU')
	ret = []
	for s in fp.readlines():
		s = s.strip()
		if len(s) == 0 or s[0] == '#': continue
		ret.append(s)
	fp.close()
	return ret
def getconf(conffile):
	fp = open(conffile, 'rU')
	ret = []
	cur = dict()
	for s in fp.readlines() + ['type=nonsense']:
		s = s.strip()
		if len(s) == 0 or s[0] == '#': continue
		if s[0: 5] == 'type=':
			if len(cur) > 0:
				ret.append(cur)
				cur = dict()
		pos = s.find('=')
		if pos != -1:
			tmp = s[pos + 1: ]
			if tmp[0] == '%': tmp = gettable(tmp[1: ])
			cur[s[0: pos]] = tmp
	fp.close()
	return ret
def domain_match(regex, target):
	regex = regex.split('.')
	target = target.split('.')
	tmp = 1
	j = 1
	l = len(regex)
	while regex[j - 1] == '*':
		tmp |= 1 << j
		j += 1
	for i in target:
		tmp2 = 0
		j = 0
		while tmp > 0:
			if tmp & 1:
				if j > 0 and regex[j - 1] == '*': tmp2 |= 1 << j
				if j < l and (regex[j] == '*' or regex[j] == '?' or regex[j] == i): tmp2 |= 1 << (j + 1)
			j += 1
			tmp >>= 1
		tmp = tmp2
		if tmp == 0: return False
	return (tmp & (1 << l)) > 0
def ipv4_match(rule, target):
	try:
		ip, netlen = re.match(r'^([0-9.]*)\/([0-9]*)$', rule).groups()
		netlen = int(netlen)
	except:
		ip, netlen = rule, 32
	try:
		ip = struct.unpack('!I', inet_pton(socket.AF_INET, ip))[0]
		tgtip = struct.unpack('!I', inet_pton(socket.AF_INET, target))[0]
	except: return False
	subnet = (1 << 32) - (1 << 32 - netlen)
	return (tgtip & subnet) == (ip & subnet)
def ipv6_match(rule, target):
	try:
		ip, netlen = re.match(r'^\[([0-9a-fA-F:]*)\]\/([0-9]*)$', rule).groups()
		netlen = int(netlen)
	except:
		try:
			ip, netlen = re.match(r'^\[([0-9a-fA-F:]*)\]$', rule).group(1), 128
		except: return False
	try:
		ip = (lambda x: (x[0] << 64) + x[1]) (struct.unpack('!QQ', inet_pton(socket.AF_INET6, ip)))
		tgtip = (lambda x: (x[0] << 64) + x[1]) (struct.unpack('!QQ', inet_pton(socket.AF_INET6, target)))
	except: return False
	subnet = (1 << 128) - (1 << 128 - netlen)
	return (tgtip & subnet) == (ip & subnet)
def port_match(rule, port):
	for portsect in rule.split(','):
		try:
			try:
				portstart, portend = map(int, re.search(r'^(\d+)-(\d+)', portsect).groups())
			except:
				portstart = portend = int(portsect)
			if port >= portstart and port <= portend:
				return True
		except: pass
	return False
def filtered(addr, port, filterlist, match):
	for fil in filterlist:
		portmatched = True
		portsect = re.search(r':([^\]]*)$', fil)
		if portsect is not None:
			portsect = portsect.group(1)
			portmatched = port_match(portsect, port)
			fil = fil[: -len(portsect)-1]
		if portmatched and match(fil, addr):
			return True
	return False
