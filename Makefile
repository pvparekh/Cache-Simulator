all: first

first: first.c
	gcc -g -Wall -Werror -fsanitize=address,undefined -g first.c -o first -lm


clean: 
	rm -rf first
