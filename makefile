LDLIBS=-lpcap

all: send-arp

main.o: ethhdr.h arphdr.h main.cpp

arphdr.o: arphdr.h arphdr.cpp

ethhdr.o: ethhdr.h ethhdr.cpp

send-arp: main.o arphdr.o ethhdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o
