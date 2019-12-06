driver: driver.o
	ld -m elf_i386 -N driver.o -o driver

driver.o: driver.s
	as --32 driver.s -o driver.o
