all: sealenv openenv

sealenv: seal_env.cpp
		gcc -Wall seal_env.cpp -lcrypto -o sealenv
openenv: open_env.cpp
		gcc -Wall open_env.cpp -lcrypto -o openenv
run:
		./sealenv
		./openenv
		cmp plaintext.txt decrypted.txt
