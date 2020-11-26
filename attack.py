import numpy as np
from hexutils import *


def find_mat(enc, r, l, f):
	a = np.zeros((l, l), dtype=int)
	b = np.zeros((l, l), dtype=int)

	# compute matrix A
	u = strhex_to_bin_array('0x00000000', 32)
	for j in range(l):
		e = np.zeros((l,), dtype=int)
		e[j] = 1
		x = enc(u, e, r, l, f)
		x = x.reshape((32, 1))
		a[:, j] = x[:, 0]

	# compute matrix B
	k = strhex_to_bin_array('0x00000000', 32)
	for j in range(l):
		e = np.zeros((l,), dtype=int)
		e[j] = 1
		x = enc(e, k, r, l, f)
		x = x.reshape((32, 1))
		b[:, j] = x[:, 0]

	return a, b


def find_key_kpa(a, b, u, x):
	a_inv = np.linalg.inv(a)
	a_det = np.linalg.det(a)
	a1 = (a_inv * a_det)
	a1 = np.mod(a1, 2)
	#print("inverted a:")
	#print(a1)
	k = np.dot(a1, (x + np.dot(b, u)))
	k = np.rint(k).astype(int)  # the previous arrays are all float with some errors
	#print("key found: ", k)

	return np.mod(k, 2)


def meet_in_the_middle(n1, n2, enc, dec, u, x, f, l):
	r = 13  # number of rounds
	l1 = []
	l2 = []
	# generate n1 random guesses for k1 and the corresponding encrypted cyphertexts
	while len(l1) < n1:
		k1 = np.random.randint(0, 2, l, dtype=int)
		x1 = enc(u, k1, r, l, f)
		l1.append([bin_array_to_strhex(k1), bin_array_to_strhex(x1)])
	# generate n2 random guesses for k2 and the corresponding decrypted plaintexts
	while len(l2) < n2:
		k2 = np.random.randint(0, 2, l, dtype=int)
		u2 = dec(x, k2, r, l, f)
		l2.append([bin_array_to_strhex(k2), bin_array_to_strhex(u2)])

	# search for matches between x1 and u2
	matches = []
	l1 = np.array(l1)
	l2 = np.array(l2)
	print(l1.shape, l2.shape)

	commons, mask1, mask2 = np.intersect1d(l1[:, 1], l2[:, 1], return_indices=True)
	print("Found matches: ", len(mask1))
	for i in range(len(mask1)):
		matches.append([l1[mask1[i], 0], l2[mask2[i], 0]])
	return matches


def meet_in_the_middle_sequential(n1, n2, enc, dec, u, x, f, l):
	r = 13  # number of rounds
	l1 = []
	l2 = []
	n1 = max(n1, 2 ** l)
	n2 = max(n2, 2 ** l)
	# generate n1 random guesses for k1 and the corresponding encrypted cyphertexts
	for i in range(n1):
		k1 = hex(i)
		x1 = enc(u, strhex_to_bin_array(k1, l), r, l, f)
		l1.append([k1, bin_array_to_strhex(x1)])

	for i in range(n2):
		k2 = hex(i)
		u2 = dec(x, strhex_to_bin_array(k2, l), r, l, f)
		l2.append([k2, bin_array_to_strhex(u2)])

	# search for matches between x1 and u2
	matches = []
	l1 = np.array(l1)
	l2 = np.array(l2)
	print(l1.shape, l2.shape)

	commons, mask1, mask2 = np.intersect1d(l1[:, 1], l2[:, 1], return_indices=True)
	print("Found matches: ", len(mask1))
	for i in range(len(mask1)):
		matches.append([l1[mask1[i], 0], l2[mask2[i], 0]])
	return matches