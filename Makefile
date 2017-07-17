all : output

output : main.o dumpcode.o deEncapsulate.o print_packet.o
	gcc -o output main.o dumpcode.o deEncapsulate.o print_packet.o -lpcap

dumpcode.o : dumpcode.c dumpcode.h
	gcc -c -o dumpcode.o dumpcode.c

deEncapsulate.o : deEncapsulate.c deEncapsulate.h data_type.h
	gcc -c -o deEncapsulate.o deEncapsulate.c

print_packet.o : print_packet.c print_packet.h deEncapsulate.h data_type.h
	gcc -c -o print_packet.o print_packet.c

main.o : main.c dumpcode.h deEncapsulate.h data_type.h print_packet.h
	gcc -c -o main.o main.c

clean :
	rm -f *.o output