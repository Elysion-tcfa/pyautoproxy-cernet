import threading, time

class Cache:
	def __init__(self):
		self.lock = threading.Lock()
		self.cache = {}

	def lookup(self, key):
		self.lock.acquire()
		if key in self.cache and time.time() - self.cache[key][0] < 300.:
			val = self.cache[key][1]
		else:
			val = None
		self.lock.release()
		return val

	def insert(self, key, val):
		self.lock.acquire()
		self.cache[key] = (time.time(), val)
		self.lock.release()

	def cleanup(self):
		now = time.time()
		self.lock.acquire()
		newcache = {}
		for key in self.cache:
			if now - self.cache[key][0] < 300.:
				newcache[key] = self.cache[key]
		self.cache = newcache
		self.lock.release()

	def flush(self):
		self.lock.acquire()
		self.cache = {}
		self.lock.release()
