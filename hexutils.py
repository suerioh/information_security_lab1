import numpy as np


def strhex_to_bin_array(s, l):
	b = bin(int(s, 16))[2:]
	a = np.array(list(b), dtype=int)
	pad = l - a.shape[0]
	a = np.pad(a, (pad, 0), 'constant')
	return a


def bin_array_to_strhex(a):
	b = ""
	for x in a:
		b += str(x)
	h = hex(int(b, 2))
	return h