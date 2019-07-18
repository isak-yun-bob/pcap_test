all : pcap_homework

pcap_test: main.o
	g++ -g -o pcap_homework main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f pcap_homework
	rm -f *.o

