def gettable(fpath):
	fp = open(fpath, 'rU')
	ret = []
	for s in fp.readlines():
		s = s.rstrip('\r\n')
		if len(s) == 0 or s[0] == '#': continue
		cur = filter(lambda x: len(x) > 0, s.replace('\t', ' ').split(' '))
		if len(cur) > 0: ret.append(cur)
	fp.close()
	return ret
def getconf():
	fp = open('proxy.conf', 'rU')
	ret = []
	cur = dict()
	for s in fp.readlines() + ['type=nonsense']:
		s = s.rstrip('\r\n')
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
def match(regex, target):
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
def filtered(addr, filterlist):
	for fil in filterlist:
		if match(fil[0], addr):
			return True
	return False
