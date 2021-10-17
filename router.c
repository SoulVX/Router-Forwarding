#include "skel.h"

typedef struct {
	uint32_t prefix;
	uint32_t next;
	uint32_t mask;
	int interface;
} rtable_entry;

typedef struct {
	uint32_t ip;
	uint8_t mac[6];
} arptable_entry;

typedef struct ether_header ether_header;
typedef struct iphdr iphdr;

void read_rtable(rtable_entry *rtable, int *rtable_size, char* name) {
	FILE *input = fopen(name, "r");
    DIE(input == NULL, "Failed to open rtable0.txt");
	char line[100], prefix[20], next[20], mask[20];
	int interface, i = 0;
	while (fgets(line, 200, input)) {
		sscanf(line, "%s %s %s %d", prefix, next, mask, &interface);
		rtable[i].prefix = htonl(inet_addr(prefix));
		rtable[i].next= htonl(inet_addr(next));
		rtable[i].mask = htonl(inet_addr(mask));
		rtable[i++].interface = interface;
	}
	*rtable_size = i;
}

void read_arptable(arptable_entry *arptable, int *arptable_size, char *name) {
	FILE *input = fopen(name, "r");
	char line[50], ip[20], mac[20];
	int i = 0;
	while (fgets(line, 50, input)) {
		sscanf(line, "%s %s", ip, mac);
		inet_pton(AF_INET, ip, &arptable[i].ip);
		arptable[i].ip = htonl(arptable[i].ip);
		hwaddr_aton(mac, arptable[i++].mac);
	}
	*arptable_size = i;
}

rtable_entry *find_best_match(rtable_entry *rtable, int rtable_size, __uint32_t ip) {
	__uint32_t max = 0;
	int poz = -1;
	for(int i = 0; i < rtable_size; i++) {
		if((rtable[i].mask & ip) == rtable[i].prefix && rtable[i].mask > max) {
			max = rtable[i].mask;
			poz = i;
		}
	}
	if(poz != -1)
		return &rtable[poz];
	return NULL;
}

uint8_t *get_mac_from_arp(arptable_entry *arptable, int arptable_size, __uint32_t ip) {
	for(int i = 0; i <= arptable_size; i++)
		if(arptable[i].ip == ip)
			return arptable[i].mac;
	return NULL;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	//Se citeste tabelul de routare
	rtable_entry *rtable = malloc(65000*sizeof(rtable_entry));
	int rtable_size;
	read_rtable(rtable, &rtable_size, argv[1]);

	//Se citeste tabelul ARP
	arptable_entry *arptable = malloc(1000*sizeof(arptable_entry));
	int arptable_size;
	read_arptable(arptable, &arptable_size, "arp_table.txt");

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		//Se extrage header-ul de ethernet
		ether_header *eth_hdr = (ether_header *)m.payload;

		if (htons(eth_hdr->ether_type) == ETHERTYPE_IP) {
			//Se extrage header-ul de IP
			iphdr *ip_hdr = (iphdr *) (m.payload + sizeof(ether_header));

			//Discard daca checksum-ul nu este corect
			if(ip_checksum(ip_hdr, sizeof(iphdr)) != 0)
				continue;

			//Daca TTL <=1, se trimite inapoi un ICMP Time Exceeded + discard
			if(ip_hdr->ttl <= 1) {
				send_icmp_error(ip_hdr->daddr, ip_hdr->saddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 11, 0, m.interface);
				continue;
			}

			rtable_entry *best_route = find_best_match(rtable, rtable_size, htonl(ip_hdr->daddr));

			//Daca nu este gasita o ruta, se trimite inapoi un ICMP Destination unreachable + discard
			if(best_route == NULL) {
				send_icmp_error(ip_hdr->daddr, ip_hdr->saddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 3, 0, m.interface);
				continue;
			}

			//Daca pachetul este un ICMP Echo si se adreseaza router-ului, se trimite inapoi un ICMP Echo reply + discard
			if(inet_addr(get_interface_ip(m.interface)) == ip_hdr->daddr && parse_icmp(m.payload)->type == 8) {
				send_icmp(ip_hdr->daddr, ip_hdr->saddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 0, 0, m.interface, 0, 0);
				continue;
			}

			//Se updateaza header-ul IP si se recalculeaza checksum-ul
			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(iphdr));

			//Se updateaza adresele MAC sursa / destinatie din header-ul Ethernet
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			memcpy(eth_hdr->ether_dhost, get_mac_from_arp(arptable, arptable_size, best_route->next), 6);

			//Se trimite pachetul mai departe in retea
			send_packet(best_route->interface, &m);
		}
	}
}