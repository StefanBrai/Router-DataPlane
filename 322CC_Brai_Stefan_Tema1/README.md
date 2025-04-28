# Router Tema1

Acest cod implementează funcționalitățile de bază ale unui router simplificat. Router-ul gestionează pachetele IP și ARP, răspunde la cererile ARP, trimite cereri ARP când este necesar, și manipulează pachete ICMP, inclusiv echo request. Implementarea a pornit de la rezolvarea laboratorului 4.

## Funcționalități

- Tratarea pachetelor ARP (ARP Request și ARP Reply). Codul poate trimite și răspunde la cereri ARP.
- Trimiterea de răspunsuri ICMP pentru diferite cazuri (de exemplu, Echo Request, Destination Unreachable, Time Limit Exceeded).
- Pachetele IP sunt rutate către destinația lor conform tabelei de rutare (sortată prin qsort ; adresele cautate cu bsearch) încărcate la inițializarea router-ului.
- Gestionarea unei cozi de pachete așteptând rezolvarea adreselor ARP.

## API

### Funcții principale

- `send_icmp_error(uint32_t src_ip, uint32_t dest_ip, uint8_t *dest_mac, int interface, uint8_t type, uint8_t code, uint8_t *data, size_t data_len)`
  - Trimite un mesaj ICMP de eroare.
- `handle_arp_reply(struct arp_header *arp_hdr)`
  - Procesează un pachet ARP Reply.
- `handle_arp_request(struct arp_header *arp_hdr, int interface)`
  - Procesează un pachet ARP Request.
- `send_arp_request(uint32_t target_ip, int interface)`
  - Trimite un ARP Request pentru o adresă IP specificată.
- `enqueue_waiting_packet(char *packet, size_t len, uint32_t next_hop_ip, int interface)`
  - Pune un pachet în coadă în așteptarea rezolvării ARP.
- `send_waiting_packets(uint32_t ip)`
  - Trimite pachetele aflate în coadă după ce adresa ARP a fost rezolvată.

### Funcții de Utilitate

- `get_best_route(uint32_t dest_ip)`
  - Caută cea mai bună rută pentru o adresă IP destinatar folosind o căutare binară.
- `get_mac_entry(uint32_t ip_dest)`
  - Obține intrarea ARP pentru o adresă IP.

### Structuri de Date Principale

- `arp_table`: Tabel care stochează asocierile IP-MAC cunoscute de router.

- `routing_table`: Tabelă de rutare încărcată dintr-un fișier la inițializarea router-ului.

- `waiting_packets_queue`: Coada de pachete care așteaptă rezolvarea adreselor MAC prin ARP.

## Procedura de lucru

1. Inițializarea: La pornire, router-ul încarcă tabela de rutare și inițializează coada de pachete în așteptare.

2. Primirea Pachetelor: 
Router-ul primește pachete de pe oricare dintre interfețele sale.
Dacă pachetul este un ARP Request destinat router-ului, se generează un ARP Reply.
Dacă pachetul este un ARP Reply, se actualizează tabela ARP și se procesează pachetele în așteptare dacă este cazul.
Pachetele IP sunt procesate conform destinației lor. Dacă destinatarul este router-ul însuși și este un ICMP Echo Request, se trimite un Echo Reply. Altfel, se încearcă rutarea pachetului către destinație.

3. Trimiterea Pachetelor: Pachetele sunt trimise fie direct către destinație, dacă adresa MAC este cunoscută, fie sunt puse în coada de așteptare până când adresa MAC este învățată prin ARP.

## Probleme Întâmpinate

- Dificultăți în implementarea unei metode bune de a eficientiza Longest Prefix Match (LPM).

- Probleme cu ultimele două teste din cauza manipulării proaste a pachetelor ICMP ECHO.

- Dificultăți în implementarea ARP, din cauza rezolvării semi-laborioase.

## Rezolvare

Cerințele au fost rezolvate toate, integral.
