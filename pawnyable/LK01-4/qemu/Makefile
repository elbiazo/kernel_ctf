all: mov

mov: exp
	mv ./exp ./root

exp: exp.c
	musl-gcc -o $@ $< -static