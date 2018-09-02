all : airodump-ng_test

airodump-ng_test: main.o
	g++ -g -o airodump-ng_test main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f airodump-ng_test
	rm -f *.o

