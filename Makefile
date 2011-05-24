all: infector

clean:
	@rm -rf *.o infector

infector: main.o infector32.o infector64.o common.o
	gcc $^ -o $@

main.o: main.c infector.h common.h
	gcc -c $< -o $@

infector32.o: infector.c infector.h common.h parasite.h
	gcc -DBUILD32 -c $< -o $@

infector64.o: infector.c infector.h common.h parasite.h
	gcc -DBUILD64 -c $< -o $@

common.o: common.c common.h
	gcc -c $< -o $@
