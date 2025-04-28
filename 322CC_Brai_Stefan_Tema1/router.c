#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "list.h"
#include "queue.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h> // pentru ntohl(), htonl(), etc.

#define ETHERTYPE_IP 0x0800 // valoarea obisnuita pentru IPv4
#define MAX_ROUTES 100000
#define MAX_ARP_ENTRIES 256
#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_DEST_UNREACHABLE_TYPE 3
#define ICMP_TIME_EXCEEDED_TYPE 11
#define ICMP_ECHO_REQUEST_TYPE 8
#define ICMP_CODE 0
#define IP_ALEN 4 // lungimea adresei IP în octeti
#define ETH_P_ARP 0x0806
#define ARP_REQUEST 1
#define ARP_REPLY 2


struct arp_table_entry arp_table[MAX_ARP_ENTRIES];
int arp_table_size = 0;
struct route_table_entry routing_table[MAX_ROUTES];
int routing_table_size = 0;

typedef struct {
    char packet[MAX_PACKET_LEN]; // continutul pachetului
    size_t len;                  // lungimea pachetului
    uint32_t next_hop_ip;        // adresa IP a urmatorului hop
    int interface;               // interfata pe care va fi trimis pachetul
} waiting_packet;

// declaratia cozii globale de pachete
queue waiting_packets_queue;

int route_cmp(const void *a, const void *b);
struct route_table_entry *get_best_route(uint32_t ip_dest);
struct arp_table_entry *get_mac_entry(uint32_t ip_dest);
void send_icmp_error(uint32_t src_ip, uint32_t dest_ip, uint8_t *dest_mac, int interface, uint8_t type, uint8_t code, uint8_t *data, size_t data_len);
void handle_arp_reply(struct arp_header *arp_hdr);
void handle_arp_request(struct arp_header *arp_hdr, int interface);
void send_arp_request(uint32_t target_ip, int interface); 
void enqueue_waiting_packet(char *packet, size_t len, uint32_t next_hop_ip, int interface);
void send_waiting_packets(uint32_t ip);

int route_cmp(const void *a, const void *b) {
    struct route_table_entry *routeA = (struct route_table_entry *)a;
    struct route_table_entry *routeB = (struct route_table_entry *)b;
    
    // comparam pe baza lungimii mastii (in ordine descrescatoare)
    int mask_len_a = __builtin_popcount(routeA->mask);
    int mask_len_b = __builtin_popcount(routeB->mask);
    if (mask_len_a != mask_len_b) {
        return mask_len_b - mask_len_a; // descrescator
    }
    
    // daca lungimile mastii sunt egale, comparam pe baza prefixului (in ordine descrescatoare)
    // probabil irelevant pasul asta ; Update : nu mai e irelevant
    if (ntohl(routeA->prefix) < ntohl(routeB->prefix)) return 1;
    if (ntohl(routeA->prefix) > ntohl(routeB->prefix)) return -1;
    return 0;
}

struct route_table_entry *get_best_route(uint32_t dest_ip) {
    int left = 0,
    right = routing_table_size - 1, 
    mid,
    best_pos = -1;
    uint32_t max_mask = 0;
    
    while (left <= right) {
        mid = (left + right) / 2;
        if ((dest_ip & routing_table[mid].mask) == routing_table[mid].prefix) {

            if (ntohl(routing_table[mid].mask) > max_mask) { 
                max_mask = ntohl(routing_table[mid].mask);
                best_pos = mid;
            }
            right = mid - 1; 
        } else if (ntohl(dest_ip & routing_table[mid].mask) > ntohl(routing_table[mid].prefix)) {
            right = mid - 1;
        } else { 
            left = mid + 1;
        }
    }

    if (best_pos != -1) {
        return &routing_table[best_pos];
    }
    else return NULL;
}


struct arp_table_entry *get_mac_entry(uint32_t ip_dest) {    
    for (int i = 0; i < arp_table_size; i++) {
        if (arp_table[i].ip == ip_dest)
            return &arp_table[i];
    }
    return NULL;
}

void send_icmp_error(uint32_t src_ip, uint32_t dest_ip, uint8_t *dest_mac, int interface, uint8_t type, uint8_t code, uint8_t *data, size_t data_len) {
    struct ether_header eth_hdr;
    struct iphdr ip_hdr;
    struct icmphdr icmp_hdr;
    char packet[MAX_PACKET_LEN];

    //antetul eth
    get_interface_mac(interface, eth_hdr.ether_shost);
    memcpy(eth_hdr.ether_dhost, dest_mac, 6);
    eth_hdr.ether_type = htons(ETHERTYPE_IP);

    // antetul IP
    ip_hdr.version = 4;
    ip_hdr.ihl = 5;
    ip_hdr.tos = 0;
    ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + data_len);
    ip_hdr.id = 0;
    ip_hdr.frag_off = 0;
    ip_hdr.ttl = 64;
    ip_hdr.protocol = IPPROTO_ICMP;
    ip_hdr.check = 0;
    ip_hdr.saddr = dest_ip; // IP-ul routerului
    ip_hdr.daddr = src_ip; // adresa  expeditorului original

    ip_hdr.check = checksum((void *)&ip_hdr, sizeof(struct iphdr));

    // antetul ICMP
    icmp_hdr.type = type;
    icmp_hdr.code = code;
    icmp_hdr.checksum = 0;
    memset(&icmp_hdr.un, 0, sizeof(icmp_hdr.un)); // resetam restul structurii

    // pachetul ICMP
    size_t offset = 0;
    memcpy(packet, &eth_hdr, sizeof(eth_hdr));
    offset += sizeof(eth_hdr);
    memcpy(packet + offset, &ip_hdr, sizeof(ip_hdr));
    offset += sizeof(ip_hdr);
    memcpy(packet + offset, &icmp_hdr, sizeof(icmp_hdr));
    offset += sizeof(icmp_hdr);
    memcpy(packet + offset, data, data_len);
    offset += data_len;

    icmp_hdr.checksum = checksum((void *)(packet + sizeof(eth_hdr) + sizeof(ip_hdr)), sizeof(icmp_hdr) + data_len);
    memcpy(packet + sizeof(eth_hdr) + sizeof(ip_hdr), &icmp_hdr, sizeof(icmp_hdr));

    send_to_link(interface, (char *)packet, offset);
}

void enqueue_waiting_packet(char *packet, size_t len, uint32_t next_hop_ip, int interface) {
    waiting_packet *wp = malloc(sizeof(waiting_packet));
    memcpy(wp->packet, packet, len);
    wp->len = len;
    wp->next_hop_ip = next_hop_ip;
    wp->interface = interface;

    queue_enq(waiting_packets_queue, wp);
}

void send_waiting_packets(uint32_t ip) {
    queue tempQueue = queue_create();

    while (!queue_empty(waiting_packets_queue)) {
        waiting_packet* wp = (waiting_packet*)queue_deq(waiting_packets_queue);

        if (wp->next_hop_ip == ip) {
            struct arp_table_entry* mac_entry = get_mac_entry(ip);
            if (mac_entry != NULL) {
                struct ether_header* eth_hdr = (struct ether_header*)(wp->packet);
                memcpy(eth_hdr->ether_dhost, mac_entry->mac, sizeof(uint8_t) * 6);
		        get_interface_mac(wp->interface, eth_hdr->ether_shost);
                send_to_link(wp->interface, wp->packet, wp->len);
                free(wp);
            } else {
                // daca nu avem o intrare ARP, pune pachetul inapoi în coada temporara
                queue_enq(tempQueue, wp);
            }
        } else {
            // daca IP-ul nu se potriveste, pune pachetul inapoi in coada temporara
            queue_enq(tempQueue, wp);
        }
    }

    // transfera pachetele inapoi in coada de asteptare principala
    while (!queue_empty(tempQueue)) {
        queue_enq(waiting_packets_queue, queue_deq(tempQueue));
    }

    // elibereaza coada temporara
    while (!queue_empty(tempQueue)) {
        free(queue_deq(tempQueue));
    }
    free(tempQueue);
}

void handle_arp_reply(struct arp_header *arp_hdr) {
    if (ntohs(arp_hdr->op) == ARP_REPLY) {
        // actualizeaza tabela ARP
        for (int i = 0; i < MAX_ARP_ENTRIES; ++i) {
            if (arp_table[i].ip == 0 || arp_table[i].ip == arp_hdr->spa) {
                memcpy(arp_table[i].mac, arp_hdr->sha, sizeof(arp_table[i].mac));
                arp_table[i].ip = arp_hdr->spa;
                if (i == arp_table_size) arp_table_size++;
                break;
            }
        }
        
        send_waiting_packets(arp_hdr->spa);
    }
}

void handle_arp_request(struct arp_header *arp_hdr, int interface) {
    // adresa IP destinatie == adresa IP a interfetei curente
    uint32_t interface_ip = inet_addr(get_interface_ip(interface));
    if (arp_hdr->tpa == interface_ip) {
        struct ether_header eth_hdr;
        uint8_t packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
        struct arp_header *reply_arp_hdr = (struct arp_header *)(packet + sizeof(struct ether_header));

        memcpy(eth_hdr.ether_dhost, arp_hdr->sha, 6); // adresa MAC destinatie este adresa MAC sursa din solicitare
        get_interface_mac(interface, eth_hdr.ether_shost); // adresa MAC sursa este adresa MAC a interfetei
        eth_hdr.ether_type = htons(ETH_P_ARP);

        reply_arp_hdr->htype = htons(1); // Ethernet
        reply_arp_hdr->ptype = htons(ETHERTYPE_IP);
        reply_arp_hdr->hlen = 6; // lungimea adresei MAC
        reply_arp_hdr->plen = 4; // lungimea adresei IP
        reply_arp_hdr->op = htons(ARP_REPLY); // operatie ARP reply
        memcpy(reply_arp_hdr->sha, eth_hdr.ether_shost, 6); // adresa MAC sursa este adresa MAC a interfetei
        reply_arp_hdr->spa = arp_hdr->tpa; // adresa IP sursa este adresa IP destinatie din solicitare
        memcpy(reply_arp_hdr->tha, arp_hdr->sha, 6); // adresa MAC destinatie este adresa MAC sursa din solicitare
        reply_arp_hdr->tpa = arp_hdr->spa; // adresa IP destinatie este adresa IP sursa din solicitare

        memcpy(packet, &eth_hdr, sizeof(struct ether_header));

        send_to_link(interface, (char *)packet, sizeof(packet));
    }
}

void send_arp_request(uint32_t target_ip, int interface) {
    char buffer[sizeof(struct ether_header) + sizeof(struct arp_header)];
    struct ether_header *eth_hdr = (struct ether_header *)buffer;
    struct arp_header *arp_hdr = (struct arp_header *)(buffer + sizeof(struct ether_header));

    // antetul ethernet pentru ARP request
    memset(eth_hdr->ether_dhost, 0xff, 6); // adresa MAC de broadcast
    get_interface_mac(interface, eth_hdr->ether_shost); // adresa MAC a interfetei routerului
    eth_hdr->ether_type = htons(ETH_P_ARP);

    // antetul ARP
    arp_hdr->htype = htons(1); // ethernet
    arp_hdr->ptype = htons(ETHERTYPE_IP);
    arp_hdr->hlen = 6;
    arp_hdr->plen = 4;
    arp_hdr->op = htons(ARP_REQUEST);
    memcpy(arp_hdr->sha, eth_hdr->ether_shost, 6); // adresa MAC sursa
    arp_hdr->spa = inet_addr(get_interface_ip(interface)); // adresa IP sursa
    memset(arp_hdr->tha, 0, 6); // adresa MAC destinatie este necunoscuta
    arp_hdr->tpa = target_ip; // adresa IP destinatie == urmatorul hop

    send_to_link(interface, (char *)buffer, sizeof(buffer));
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);
	routing_table_size = read_rtable(argv[1], routing_table);
    waiting_packets_queue = queue_create();
    qsort(routing_table, routing_table_size, sizeof(struct route_table_entry), route_cmp);
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

        uint8_t interface_mac[6];
        get_interface_mac(interface, interface_mac);

        // verificare L2
        if (memcmp(eth_hdr->ether_dhost, interface_mac, sizeof(uint8_t)* 6)  &&
            memcmp(eth_hdr->ether_dhost, broadcast_mac, sizeof(uint8_t) * 6)) 
        {   
            continue;
        }

        if (ntohs(eth_hdr->ether_type) == ETH_P_ARP) {
            struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
            if (ntohs(arp_hdr->op) == ARP_REQUEST) {
                // ARP Request
                handle_arp_request(arp_hdr, interface);
                continue;

            } else if (ntohs(arp_hdr->op) == ARP_REPLY) {
                // ARP Reply
                handle_arp_reply(arp_hdr);
                continue;
            }
        }    
        else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
        {
        if (ip_hdr->daddr == (uint32_t)inet_addr(get_interface_ip(interface)) 
            && 
            ip_hdr->protocol != IPPROTO_ICMP) 
            continue;

        if (ip_hdr->daddr == (uint32_t)inet_addr(get_interface_ip(interface)) 
            && 
            ip_hdr->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

            // Echo Request
            if (icmp_hdr->type == ICMP_ECHO_REQUEST_TYPE) {
                icmp_hdr->type = ICMP_ECHO_REPLY_TYPE; // doar modificam in Echo Reply
                ip_hdr->daddr = ip_hdr->saddr; // inversam sursa si destinatie
                ip_hdr->saddr = inet_addr(get_interface_ip(interface)); //adresa interfetei
                icmp_hdr->checksum = 0;
                icmp_hdr->checksum = checksum((void *)icmp_hdr, len - sizeof(struct ether_header) - sizeof(struct iphdr));

                //se trimite pachetul inapoi
                send_to_link(interface, buf, len);
                continue;
            }
        }

		if (checksum((void*)ip_hdr, sizeof(struct iphdr)))
            continue;
        
        if (ip_hdr->ttl <= 1) {
            // ICMP Time Exceeded
            uint8_t data[sizeof(struct iphdr) + 8]; // antetul IP + primii 8 octeti din payload
            memcpy(data, ip_hdr, sizeof(struct iphdr) + 8);
            send_icmp_error(ip_hdr->saddr, inet_addr(get_interface_ip(interface)), eth_hdr->ether_shost, interface, ICMP_TIME_EXCEEDED_TYPE, ICMP_CODE, data, sizeof(data));
            continue;
        }

		struct route_table_entry* best_route = get_best_route(ip_hdr->daddr);
        
        if (best_route == NULL)
        {
            uint32_t src_ip = ip_hdr->saddr;

    // adresa MAC a interfetei de pe care a fost primit pachetul
            uint8_t src_mac[6];
            get_interface_mac(interface, src_mac);

    // primii 8 octeti din payload-ul pachetului IP original
            uint8_t data[sizeof(struct iphdr) + 8];
            memcpy(data, ip_hdr, sizeof(struct iphdr) + 8);

    // ICMP "Destination Unreachable" catre sursa originala
            send_icmp_error(src_ip, inet_addr(get_interface_ip(interface)), src_mac, interface, ICMP_DEST_UNREACHABLE_TYPE, ICMP_CODE, data, sizeof(data));
            continue;
        }

		ip_hdr->ttl--;
       
		ip_hdr->check = ~(~ip_hdr->check + ~(ip_hdr->ttl + 1) + ip_hdr->ttl) - 1;
        struct arp_table_entry* mac_entry = get_mac_entry(best_route->next_hop);
        if (mac_entry == NULL) {
                // adresa MAC nu este cunoscuta ; trimitem un ARP request
                send_arp_request(best_route->next_hop, best_route->interface);
                enqueue_waiting_packet(buf, len, best_route->next_hop, best_route->interface);
        
                continue;
            }

		memcpy(eth_hdr->ether_dhost, get_mac_entry(best_route->next_hop)->mac, sizeof(uint8_t) * 6);
		get_interface_mac(best_route->interface, eth_hdr->ether_shost);
		send_to_link(best_route->interface, buf, len);
        }
		else continue;
	}
}