LDLIBS=-lpcap

all: arp-spoof

main.o: ethhdr.h arphdr.h main.cpp

arphdr.o: arphdr.h arphdr.cpp

ethhdr.o: ethhdr.h ethhdr.cpp

ipv4.o: ipv4.h ipv4.cpp

arp-spoof: main.o arphdr.o ethhdr.o ipv4.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
