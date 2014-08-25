import re, socket, struct, socket, proxylib

def analyze(val, globvar):
	val = ' ' + val
	pos = 0
	newval = ''
	for match in re.finditer(r'(?<=\s)%([^\s]*)', val):
		newval += val[pos: match.start()]
		pos = match.end()
		filename = match.group(1)
		fp = open(filename, 'rU')
		newval += fp.read()
		fp.close()
	newval += val[pos: ]
	val = newval
	pos = 0
	newval = ''
	for match in re.finditer(r'(?<=\s)\$([^\s]*)', val):
		newval += val[pos: match.start()]
		pos = match.end()
		var = match.group(1)
		if var in globvar: newval += globvar[var]
	newval += val[pos: ]
	return newval[1: ]
def getconf(conffile):
	fp = open(conffile, 'rU')
	ret = {'servers': [], 'dns_servers': []}
	globvar = dict()
	cur = globvar
	glob = True
	for s in fp.readlines() + ['type=nonsense']:
		s = s.strip()
		if len(s) == 0 or s[0] == '#': continue
		if s[0: 5] == 'type=':
			if glob:
				ret = dict(cur)
				ret.update({'servers': [], 'dns_servers': []})
			elif cur['type'][0: 4] == 'dns_':
				cur['type'] = cur['type'][4: ]
				ret['dns_servers'].append(cur)
			else:
				ret['servers'].append(cur)
			cur = dict()
			glob = False
		pos = s.find('=')
		if pos != -1:
			key = s[0: pos]
			val = analyze(s[pos + 1: ], globvar)
			if not glob and key != 'type':
				if cur['type'][0: 4] == 'dns_':
					if key in ['domainaccept', 'domainexcept']:
						val = dns_filtered(filter(lambda x: x[0] != '#', val.split()))
				else:
					if key in ['ipv4accept', 'ipv4except']:
						val = filtered(filter(lambda x: x[0] != '#', val.split()), ipv4_match)
					elif key in ['ipv6accept', 'ipv6except']:
						val = filtered(filter(lambda x: x[0] != '#', val.split()), ipv6_match)
					elif key in ['domainaccept', 'domainexcept']:
						val = filtered(filter(lambda x: x[0] != '#', val.split()), domain_match)
					elif key in ['httpaccept', 'httpexcept']:
						val = http_filtered(filter(lambda x: x[0] != '#', val.split()))
			cur[key] = val
	fp.close()
	return ret
def domain_match(regex):
	regex = regex.split('.')
	l = len(regex)
	def fun(target):
		target = target.split('.')
		tmp = 1
		j = 1
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
	return fun
def ipv4_match(rule):
	try:
		ip, netlen = re.match(r'^([0-9.]*)\/([0-9]*)$', rule).groups()
		netlen = int(netlen)
	except:
		ip, netlen = rule, 32
	ip = struct.unpack('!I', socket.inet_pton(socket.AF_INET, ip))[0]
	subnet = (1 << 32) - (1 << 32 - netlen)
	def fun(target):
		tgtip = struct.unpack('!I', socket.inet_pton(socket.AF_INET, target))[0]
		return (tgtip & subnet) == (ip & subnet)
	return fun
def ipv6_match(rule):
	try:
		ip, netlen = re.match(r'^\[([0-9a-fA-F:]*)\]\/([0-9]*)$', rule).groups()
		netlen = int(netlen)
	except:
		ip, netlen = re.match(r'^\[([0-9a-fA-F:]*)\]$', rule).group(1), 128
	ip = (lambda x: (x[0] << 64) + x[1]) (struct.unpack('!QQ', socket.inet_pton(socket.AF_INET6, ip)))
	subnet = (1 << 128) - (1 << 128 - netlen)
	def fun(target):
		tgtip = (lambda x: (x[0] << 64) + x[1]) (struct.unpack('!QQ', socket.inet_pton(socket.AF_INET6, target)))
		return (tgtip & subnet) == (ip & subnet)
	return fun
def port_match(rule):
	portl = []
	for portsect in rule.split(','):
		try:
			portstart, portend = map(int, re.search(r'^(\d+)-(\d+)', portsect).groups())
		except:
			portstart = portend = int(portsect)
		portl.append((portstart, portend))
	def fun(port):
		for portstart, portend in portl:
			if port >= portstart and port <= portend:
				return True
		return False
	return fun
def httpurl_match(rule):
	def fun(url):
		return re.search(rule, url) is not None
	return fun
def filtered(filterlist, addr_match):
	filterfuns = []
	for fil in filterlist:
		portsect = re.search(r':([^\]]*)$', fil)
		if portsect is not None:
			portsect = portsect.group(1)
			addrsect = fil[: -len(portsect)-1]
			filterfuns.append((addr_match(addrsect), port_match(portsect)))
		else:
			filterfuns.append((addr_match(fil), lambda x: True))
	def fun(addr, port):
		for addrfun, portfun in filterfuns:
			if addrfun(addr) and portfun(port):
				return True
		return False
	return fun
def dns_filtered(filterlist):
	filterfuns = []
	for fil in filterlist:
		filterfuns.append(domain_match(fil))
	def fun(addr):
		for addrfun in filterfuns:
			if addrfun(addr):
				return True
		return False
	return fun
def http_filtered(filterlist):
	filterfuns = []
	for fil in filterlist:
		filterfuns.append(httpurl_match(fil))
	def fun(url):
		for urlfun in filterfuns:
			if urlfun(url):
				return True
		return False
	return fun
