from struct import pack, unpack
import functools
from math import gcd
from hashlib import sha1 as SHA
import hmac as HMAC

from crypto.PBKDF2.pbkdf2 import pbkdf2 as PBKDF2
from crypto.AES import *

import logging

logging.basicConfig(level=logging.DEBUG)

keyusage = 2

aes256_etype = 18
aes256_keysize = 32
aes256_seedsize = 32

aes128_etype = 17
aes128_keysize = 16
aes128_seedsize = 16

blocksize = 16
padsize = 1
macsize = 12
hashmod = SHA

def _mac_equal(mac1, mac2):
	# Constant-time comparison function.  (We can't use HMAC.verify
	# since we use truncated macs.)
	assert len(mac1) == len(mac2)
	res = 0
	for x, y in zip(mac1, mac2):
		res |= x ^ y
	return res == 0

def _xorbytes(b1, b2):
	# xor two strings together and return the resulting string.
	assert len(b1) == len(b2)
	t1 = int.from_bytes(b1, byteorder = 'big', signed = False)
	t2 = int.from_bytes(b2, byteorder = 'big', signed = False)
	return (t1 ^ t2).to_bytes(len(b1), byteorder = 'big', signed = False)

def _zeropad(s, padsize):
	# Return s padded with 0 bytes to a multiple of padsize.
	padlen = (padsize - (len(s) % padsize)) % padsize
	return s + b'\x00'*padlen

def _nfold(str, nbytes):
	logging.debug('===_nfold <- in: str: %s nbytes: %s' % (str.hex(), nbytes))
	# Convert str to a string of length nbytes using the RFC 3961 nfold
	# operation.

	# Rotate the bytes in str to the right by nbits bits.
	def rotate_right(str, nbits):
		num = int.from_bytes(str, byteorder ='big', signed = False)
		size = len(str)*8
		nbits %= size
		body = num >> nbits
		remains = (num << (size - nbits)) - (body << size)
		return (body + remains).to_bytes(len(str), byteorder ='big', signed = False)

	# Add equal-length strings together with end-around carry.
	def add_ones_complement(str1, str2):
		n = len(str1)
		v = []
		for i in range(0,len(str1), 1):
			t = str1[i] + str2[i]
			v.append(t)

		#v = [ord(a) + ord(b) for a, b in zip(str1, str2)]
		# Propagate carry bits to the left until there aren't any left.
		while any(x & ~0xff for x in v):
			v = [(v[i-n+1]>>8) + (v[i]&0xff) for i in range(n)]
		return b''.join(x.to_bytes(1, byteorder = 'big', signed = False) for x in v)

	# Concatenate copies of str to produce the least common multiple
	# of len(str) and nbytes, rotating each copy of str to the right
	# by 13 bits times its list position.  Decompose the concatenation
	# into slices of length nbytes, and add them together as
	# big-endian ones' complement integers.
	slen = len(str)
	lcm = int(nbytes * slen / gcd(nbytes, slen))
	bigstr = b''.join((rotate_right(str, 13 * i) for i in range(int(lcm / slen))))
	slices = (bigstr[p:p+nbytes] for p in range(0, lcm, nbytes))

	t = functools.reduce(add_ones_complement,  slices)
	logging.debug('===_nfold -> ret: %s' % t.hex())
	return t

def basic_encrypt(key, plaintext):
	assert len(plaintext) >= 16
	aes = AESModeOfOperationCBC(key, b'\x00' * 16)
	ctext = aes.encrypt(_zeropad(plaintext, 16))
	if len(plaintext) > 16:
		# Swap the last two ciphertext blocks and truncate the
		# final block to match the plaintext length.
		lastlen = len(plaintext) % 16 or 16
		ctext = ctext[:-32] + ctext[-16:] + ctext[-32:-16][:lastlen]
	return ctext

def basic_decrypt(key, ciphertext):
	assert len(ciphertext) >= 16
	aes = AESModeOfOperationECB(key)
	if len(ciphertext) == 16:
		return aes.decrypt(ciphertext)
	# Split the ciphertext into blocks.  The last block may be partial.
	cblocks = [ciphertext[p:p+16] for p in range(0, len(ciphertext), 16)]
	lastlen = len(cblocks[-1])
	# CBC-decrypt all but the last two blocks.
	prev_cblock = b'\x00' * 16
	plaintext = b''
	for b in cblocks[:-2]:
		plaintext += _xorbytes(aes.decrypt(b), prev_cblock)
		prev_cblock = b
	# Decrypt the second-to-last cipher block.  The left side of
	# the decrypted block will be the final block of plaintext
	# xor'd with the final partial cipher block; the right side
	# will be the omitted bytes of ciphertext from the final
	# block.
	b = aes.decrypt(cblocks[-2])
	lastplaintext =_xorbytes(b[:lastlen], cblocks[-1])
	omitted = b[lastlen:]
	# Decrypt the final cipher block plus the omitted bytes to get
	# the second-to-last plaintext block.
	plaintext += _xorbytes(aes.decrypt(cblocks[-1] + omitted), prev_cblock)
	return plaintext + lastplaintext

def derive(key, constant, seedsize):
	# RFC 3961 only says to n-fold the constant only if it is
	# shorter than the cipher block size.  But all Unix
	# implementations n-fold constants if their length is larger
	# than the block size as well, and n-folding when the length
	# is equal to the block size is a no-op.
	logging.debug('==derive <- in: constant: %s seedsize: %s' % (constant.hex(), seedsize))
	plaintext = _nfold(constant, blocksize)
	rndseed = b''
	while len(rndseed) < seedsize:
		ciphertext = basic_encrypt(key, plaintext) #encrypting the constant string "kerberos" with the
		rndseed += ciphertext
		plaintext = ciphertext
	t = rndseed[0:seedsize]
	logging.debug('==derive -> ret: %s ' % t.hex())
	return t

def string_to_key_aes(string, salt, seedsize, params):
	"""
	Generates the AES128/256 key used for encryption/decryption
	based on the user's credentials (domainname, username, password)

	params variable controls the iteration count for PBKDF2
	seedsize variable value is the only difference between aes256 and aes128
	"""
	logging.debug('== string_to_key_aes')
	(iterations,) = unpack('>L', params or b'\x00\x00\x10\x00') #PBKDF2 iteration count
	seed = PBKDF2(string, salt, iterations, seedsize)
	logging.debug('== seed: %s' % seed.hex())
	key_bytes = derive(seed, 'kerberos'.encode(), seedsize)
	return key_bytes

def decrypt(key, keyusage, ciphertext, seedsize):
	logging.debug('== decrypt')
	ki = derive(key, pack('>IB', keyusage, 0x55), seedsize)
	logging.debug('== ki: %s' % ki.hex())
	ke = derive(key, pack('>IB', keyusage, 0xAA), seedsize)
	logging.debug('== ke: %s' % ke.hex())
	if len(ciphertext) < blocksize + macsize:
		raise ValueError('ciphertext too short')
	basic_ctext, mac = ciphertext[:-macsize], ciphertext[-macsize:]
	if len(basic_ctext) % padsize != 0:
		raise ValueError('ciphertext does not meet padding requirement')
	basic_plaintext = basic_decrypt(ke, basic_ctext)
	hmac = HMAC.new(ki, basic_plaintext, hashmod).digest()
	logging.debug('== hmac: %s' % hmac.hex())
	expmac = hmac[:macsize]
	if not _mac_equal(mac, expmac):
		raise Exception('ciphertext integrity failure')
	# Discard the confounder.
	return basic_plaintext[blocksize:]


if __name__ == '__main__':
	users = ['srv_http', 'srv_mssql']
	testcases = ['128', '256']

	domain = 'TEST.corp'

	for user in users:
		if user == 'srv_http':
			username = 'srv_http'
			pw = 'yLM2t3TMtLHMt5XlfuHT'
		else:
			username = 'srv_mssql'
			pw = '3toDMPZjKyKuSr68M6l5'

		for testcase in testcases:
			for i in range(10):
				logging.debug('============ CASE:%d USER:%s CIPHER: AES%s' % (i, username, testcase))
				logging.debug('===== calculating key from password')
				salt = (domain.upper() + username).encode()
				if testcase == '128':
					key_bytes = string_to_key_aes(pw.encode(), salt, aes128_seedsize, params=None)
					seedsize = aes128_seedsize
				else:
					key_bytes = string_to_key_aes(pw.encode(), salt, aes256_seedsize, params=None)
					seedsize = aes256_seedsize

				logging.debug('key_bytes: %s' % key_bytes.hex())
				with open('test_cases\\%s\\aes%s\\tgs_%s_encpart_%d.txt' % (user, testcase, user, i)) as enc:
					enc_ticket = bytes.fromhex(enc.read().strip())
				with open('test_cases\\%s\\aes%s\\tgs_%s_dec_%d.txt' % (user, testcase, user, i)) as dec:
					dec_ticket_vrfy = bytes.fromhex(dec.read().strip())
				logging.debug('=====decrypting ticket')
				dec_ticket = decrypt(key_bytes, keyusage, enc_ticket, seedsize)

				if dec_ticket != dec_ticket_vrfy:
					raise Exception('Test case %s %s %d failed!' % (user, testcase, i))

				logging.debug('')

	print('All tests passed!')
