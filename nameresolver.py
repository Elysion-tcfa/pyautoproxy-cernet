import dns.resolver, time, threading
from proxylib import ProxyException
import cache

def _resolve_ipv4(conf):
	return not 'ipv4' in conf or conf['ipv4'] != '0'
def _resolve_ipv6(conf):
	return not 'ipv6' in conf or conf['ipv6'] != '0'

class BaseNameResolver:
	def __init__(self, addr, conf):
		self.conf = conf
		self.addr = addr
		self.timeout = 30.
		if 'timeout' in conf:
			self.timeout = float(conf['timeout'])
	def resolve(self):
		pass

class DirectNameResolver(BaseNameResolver):
	def resolve(self):
		def resolve_ipv6():
			resolver = dns.resolver.Resolver()
			resolver.lifetime = self.timeout
			try:
				self.ipv6_ans = map(lambda ans: (4, ans.address),
						resolver.query(self.addr, 'AAAA')[0: 1])
			except: pass
		self.ipv6_ans = []
		ans = []
		if _resolve_ipv6(self.conf):
			thr = threading.Thread(target = resolve_ipv6)
			thr.start()
		if _resolve_ipv4(self.conf):
			resolver = dns.resolver.Resolver()
			resolver.lifetime = self.timeout
			try:
				ans = map(lambda ans: (1, ans.address),
						resolver.query(self.addr, 'A')[0: 1])
			except: pass
		if _resolve_ipv6(self.conf):
			thr.join()
		return self.ipv6_ans + ans

class ProxyNameResolver(BaseNameResolver):
	def resolve(self):
		def resolve_ipv6():
			resolver = dns.resolver.Resolver()
			resolver.nameservers = self.conf['server'].split()
			resolver.lifetime = self.timeout
			try:
				self.ipv6_ans = map(lambda ans: (4, ans.address),
						resolver.query(self.addr, 'AAAA')[0: 1])
			except: pass
		self.ipv6_ans = []
		ans = []
		if _resolve_ipv6(self.conf):
			thr = threading.Thread(target = resolve_ipv6)
			thr.start()
		if _resolve_ipv4(self.conf):
			resolver = dns.resolver.Resolver()
			resolver.nameservers = self.conf['server'].split()
			resolver.lifetime = self.timeout
			try:
				ans = map(lambda ans: (1, ans.address),
						resolver.query(self.addr, 'A')[0: 1])
			except: pass
		if _resolve_ipv6(self.conf):
			thr.join()
		return self.ipv6_ans + ans

_cache = cache.Cache()
_classdict = {'direct': DirectNameResolver,
		'proxy': ProxyNameResolver}

def _domain_filtered(addr, conf):
	return 'domainaccept' in conf and not conf['domainaccept'](addr) \
			or 'domainexcept' in conf and conf['domainexcept'](addr)

class NameResolverSelector:
	def __init__(self, addr, conf):
		self.lifetime = 30.
		if 'dns_lifetime' in conf:
			self.lifetime = float(conf['dns_lifetime'])
		self.addr = addr
		self.conf = conf
	def resolve(self):
		ans = _cache.lookup(self.addr)
		if ans is not None:
			return ans
		deadline = time.time() + self.lifetime
		for serverconf in self.conf['dns_servers']:
			if _domain_filtered(self.addr, serverconf):
				continue
			resolver = _classdict[serverconf['type']](self.addr, serverconf)
			resolver.timeout = min(resolver.timeout, deadline - time.time())
			ans = resolver.resolve()
			if ans:
				_cache.insert(self.addr, ans)
				return ans
		raise ProxyException('cannot resolve hostname')
