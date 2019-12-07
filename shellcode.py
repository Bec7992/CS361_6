import sys
import itertools as it

alpha_code = []

def main():
	if len(sys.argv) - 1 != 1:
		print("Wrong number of arguments")

	copy_ecx_to_esi() # pust start of code address in esi
	eax_ff()

	with open(sys.argv[1], "rb") as f:
		all_bytes = bytes(f.read())

		for i in reversed(all_bytes):
			if alpha_check(i):
				cat_alpha(bytes([i]))
			elif i < 128:
				cat_xor(i)
			else:
				cat_not(i)

		copy_esi_to_edi() # put start of code address in edi

		# push these to stack to be popped by ecx
		cat_alpha(b'\x30')
		cat_alpha(b'\x30')
		cat_not(b'\xf3'[0]) # '0' xor 0xf3 = 0xc3
		cat_alpha(b'\x30')
		alpha_code.append("Y") #pop ecx
		copy_ecx_to_edx() #edx (dh) now has what will xor with '0' (last byte) to make c3

		size = len(alpha_code) # get eax = length of byte string plus code before the comming c3 / 2
		size = size + 3 + 80 + 30 + 1 + 1# size + xor length + longest to push size to stack + 2*cat_xor(b'\x00'[0]) + pop eax + copy_edx_to_edi() size + push esp

		#the following section pushes each byte of int size to the stack
		binary = bin(size // 2)
		if size % 2:
			binary = bin((size + 1) // 2)
		binary = binary[2:]
		print(binary)
		print("len = " + str(len(binary)))

		cat_xor(b'\x00'[0])
		cat_xor(b'\x00'[0])

		end = len(binary) - 9 #second byte
		start = end - 8 + 1
		if start < 0:
			start = 0
		padded_binary = binary[start : end+1]
		print(padded_binary)
		for i in range(len(binary[start : end+1]), 8):
			padded_binary = "0" + padded_binary
		print(padded_binary)
		binary_byte = bytes([int(padded_binary, 2)])
		print(binary_byte)
		if alpha_check(binary_byte[0]):
			# add 32 bytes of padding
			for i in range(0, 32):
				alpha_code.append("A")
			cat_alpha(binary_byte)
		elif binary_byte[0] < 128:
			# add 25 bytes of padding
			for i in range(0, 25):
				alpha_code.append("A")
			cat_xor(binary_byte[0])
		else:
			cat_not(binary_byte[0]) # 35 bytes long

		end = len(binary) - 1 #first byte
		start = end - 8 + 1
		binary_byte = bytes([int(binary[start : end+1], 2)])
		print(binary_byte)
		if alpha_check(binary_byte[0]):
			# add 32 bytes of padding
			for i in range(0, 32):
				alpha_code.append("A")
			cat_alpha(binary_byte)
		elif binary_byte[0] < 128:
			#add 25 bytes of padding
			for i in range(0, 25):
				alpha_code.append("A")
			cat_xor(binary_byte[0])
		else:
			cat_not(binary_byte[0]) # 35 bytes long

		if size % 2:
			alpha_code.append("A") # if size is odd, add this padding
		alpha_code.append("X") # pop eax TODO: eax only has 0x75 for sh.bin, second byte must be getting cut off.

		alpha_code.append("0") # xor [edi + 2*eax] dh
		alpha_code.append("4")
		alpha_code.append("G")

		alpha_code.append("T") # push esp

		alpha_code.append("0") # this is alphanumeric X1 that xors with Y1 to equal c3

		for i in alpha_code:
			print(i, end = '')

# 8 bytes
def cat_alpha(byte):
	alpha_code.append("h") # push is this the right code? could it also be "h", 68? j is byte, h is double

	to_add = "aaa" + byte.decode("ascii")
	for i in to_add:
		alpha_code.append(i) # byte to push + ??

	for i in range(0, 3):
		alpha_code.append("D") # inc esp. get rid of 3 of 4 00 bytes

# 15 bytes
def cat_xor(byte):
	byte_list = alpha_xor(byte)

	alpha_code.append("h") # push <imm32>
	to_add = "aaa" + bytes([byte_list[0]]).decode("ascii")
	for i in to_add:
		alpha_code.append(i)

	alpha_code.append("X") # pop X1aaa to eax
	
	alpha_code.append("5") # xor eax with Y1aaa to get B1000000
	to_xor = "aaa" + bytes([byte_list[1]]).decode("ascii")
	for i in to_xor:
		alpha_code.append(i)

	alpha_code.append("P") # push eax
	for i in range(0, 3):
		alpha_code.append("D") # inc esp. get rid of 3 of 4 00 bytes

# cat_xor + 25 bytes
def cat_not(byte):
	cat_xor(~bytes([byte])[0] & 255)

	alpha_code.append("T") # push %esp, 54
	alpha_code.append("Y") # pop %ecx, 59

	eax_ff()
	copy_eax_to_ebx()

	alpha_code.append("0") # xor [ecx] bh (2nd 8bit of %ebx)
	alpha_code.append("9")

def eax_ff():
	# pop aaaa into eax
	alpha_code.append("h") # push aaaa to stack
	to_add = "aaaa"
	for i in to_add:
		alpha_code.append(i)
	alpha_code.append("X") # pop aaaa to eax

	alpha_code.append("5") # xor eax with aaaa to get 00000000
	to_add = "aaaa"
	for i in to_add:
		alpha_code.append(i)
	alpha_code.append("H") # dec eax to get ffffffff

# used for category_NOT
def copy_eax_to_ebx():
	alpha_code.append("P") # push eax ecx edx ebx eax ebp esi eax
	alpha_code.append("Q")
	alpha_code.append("R")
	alpha_code.append("P")
	alpha_code.append("P")
	alpha_code.append("U")
	alpha_code.append("V")
	alpha_code.append("W")
	alpha_code.append("a") #popad

# used at start of code to save start address for later
def copy_ecx_to_esi():
	alpha_code.append("P")
	alpha_code.append("Q")
	alpha_code.append("R")
	alpha_code.append("S")
	alpha_code.append("P")
	alpha_code.append("U")
	alpha_code.append("Q")
	alpha_code.append("W")
	alpha_code.append("a")

# used at end of code to get start address in edx
def copy_ecx_to_edx():
	alpha_code.append("P")
	alpha_code.append("Q")
	alpha_code.append("Q")
	alpha_code.append("S")
	alpha_code.append("P")
	alpha_code.append("U")
	alpha_code.append("V")
	alpha_code.append("W")
	alpha_code.append("a")

def copy_esi_to_edi():
	alpha_code.append("P")
	alpha_code.append("Q")
	alpha_code.append("R")
	alpha_code.append("S")
	alpha_code.append("P")
	alpha_code.append("U")
	alpha_code.append("V")
	alpha_code.append("V")
	alpha_code.append("a")

def alpha_check(byte):
	if byte < ord('0'):
		return False
	elif byte <= ord('9'):
		return True
	elif byte < ord('A'):
		return False
	elif byte <= ord('Z'):
		return True
	elif byte < ord('a'):
		return False
	elif byte <= ord('z'):
		return True
	else:
		return False

def alpha_xor(byte):
	for i in it.chain(range(48, 58), range(65, 91), range(97, 123)):
		for j in it.chain(range(i, 58), range(max(i, 65), 91), range(max(i, 97), 123)):
			if i ^ j == byte:
				return [i, j]

if __name__ == "__main__":
	main()