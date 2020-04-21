all: hash1 hash2

hash1: hash.c
		gcc -Wall hash.c -lcrypto -o hash
hash2: hash2.c
		gcc -Wall hash2.c -lcrypto -o hash2
run:
		./hash
		./hash2
