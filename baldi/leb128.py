import struct

def leb128_encode(x):
	out = []
	while x != 0:
		out.append(x & 0x7f | 0x80)
		x >>= 7
	# print(map(hex, out))
	if len(out):
		out[-1] &= 0x7f
	return bytearray(out)

def leb128s_encode(x):
	out = []
	more = 1
	while more > 0:
		byte = x & 0x7f
		x >>= 7
		if (x == 0 and (byte & 0x40) == 0) or (x == -1 and (byte & 0x40) != 0):
			more = 0
		if more != 0:
			byte |= 0x80
		# print(hex(byte), more)
		out.append(byte)
	return bytearray(out)


def leb128_decode(s):
	x = 0
	i, l = 0, 0
	for c in s:
		x |= (ord(c) & 0x7f) << i
		i += 7
		l += 1
		if c & 0x80 == 0:
			break
	return x, l

def leb128s_decode(s):
	x = 0
	i, l = 0, 0
	while True:
		byte = s[l]
		x |= (byte & 0x7f) << i
		i += 7
		l += 1
		if byte < 0x80:
			break
	if byte & 0x40:
		x |= -(1 << i)
	return x, l

if __name__ == '__main__':
	leb = leb128s_encode(12460)
	print(str(leb).encode('hex'))
	x, l = leb128s_decode(leb)
	print(x, l)
