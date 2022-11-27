all: mov_root


exp: exp.c
	musl-gcc -o $@ $< -static

mov_root: exp
	mv ./exp ./root