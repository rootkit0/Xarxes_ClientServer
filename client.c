/*
USAGE
    client.py [-c <config_file>] [-f <boot_file>] [-d debug mode]
AUTHOR
    Xavier Berga Puig <xbp1@alumnes.udl.cat>
LICENSE
    This software is published under the GNU Public License GPLv3
    https://www.github.com/rootkit0/Practica_Xarxes
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <time.h>

#include <arpa/inet.h>
#include <sys/socket.h>

/* Variables i estructures globals */
char *cfg_client = "client.cfg";
char *cfg_boot = "boot.cfg";
bool debug_mode = false;

char *nom, *mac, *server_ip;
int server_port, socket_udp, socket_tcp;

char time_buffer[100];

struct sockaddr_in serverAddr_udp;
struct sockaddr_in serverAddr_tcp;

struct pdu_udp {
    unsigned char tipus_paquet;
    char nom_eq[7];
    char mac_eq[13];
    char num_aleatori[7];
    char dades[50];
};

struct pdu_tcp {
    unsigned char tipus_paquet;
    char nom_eq[7];
    char mac_eq[13];
    char num_aleatori[7];
    char dades[150];
};

/* Paquets fase registre */
struct pdu_udp register_req;
struct pdu_udp register_ack;
/* Paquets fase alive */
struct pdu_udp alive_inf;
struct pdu_udp alive_ack;
/* Paquets comanda send-conf */
struct pdu_tcp send_file;
struct pdu_tcp send_ack;
struct pdu_tcp send_data;
struct pdu_tcp send_end;
/* Paquets comanda get-conf */
struct pdu_tcp get_file;
struct pdu_tcp get_ack;
struct pdu_tcp get_data;
struct pdu_tcp get_end;

/* Copio el string apuntat pel punter s al punter d */
char *strdup (const char *s) {
    char *d = malloc (strlen (s) + 1);
    if (d == NULL) return NULL;
    strcpy (d,s);
    return d;
}

/* Fases del client */
bool fase_registre();
void *fase_alive();
void *fase_comandes();

/* Funcio principal */
int main(int argc, char *argv[]) {
    /* Tracto els parametres */
    int opt = 0;
    while((opt = getopt(argc, argv, "d:c:f:")) != -1) {
        switch(opt) {
            case 'd':
                debug_mode = true;
                break;
            case 'c':
                cfg_client = optarg;
                break;
            case 'f':
                cfg_boot = optarg;
                break;
            case '?':
                if(optopt == 'c') {
                    printf("Arxiu cfg del client no especificat\n");
                    exit(1);
                }
                else if(optopt == 'f') {
                    printf("Arxiu cfg de l'equip de xarxa no especificat\n");
                    exit(1);
                }
                else {
                    printf("Opcio no valida\n");
                    exit(1);
                }
                break;
        }
    }
    if(debug_mode) {
        time_t now = time (0);
        strftime(time_buffer, 100, "%H:%M:%S", localtime(&now));
        printf("%s: DEBUG. => Llegits paràmetres línia de comandes\n", time_buffer);
    }
    /* Llegeixo el fitxer de configuracio */
    FILE *cfg_file = fopen(cfg_client, "r");
    char line[256], *word;
    int count = 0;
    while(fgets(line, sizeof(line), cfg_file)) {     
        word = strtok(line, " ");
        word = strtok(NULL, "\n");
        if(count == 0) {
            nom = strdup(word);
        }
        else if(count == 1) {
            mac = strdup(word);
        }
        else if(count == 2) {
            server_ip = strdup(word);
        }
        else {
            server_port = atoi(word);
        }
        ++count;
    }
    if(debug_mode) {
        time_t now = time (0);
        strftime(time_buffer, 100, "%H:%M:%S", localtime(&now));
        printf("%s: DEBUG. => Llegits paràmetres arxiu de configuracio\n", time_buffer);
    }
    fclose(cfg_file);
    /* Creo un socket UDP */
    if((socket_udp = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "No puc obrir el socket\n");
        exit(1);
    }
    /* Configuro el struct d'adreçes pel socket UDP */
    serverAddr_udp.sin_family = AF_INET;
    serverAddr_udp.sin_port = htons(server_port);
    serverAddr_udp.sin_addr.s_addr = inet_addr("127.0.0.1");
    memset(serverAddr_udp.sin_zero, '\0', sizeof serverAddr_udp.sin_zero);
    /* Inicio la fase de registre */
    time_t now = time (0);
    strftime(time_buffer, 100, "%H:%M:%S", localtime(&now));
    printf("%s: MSG. => Equip passa a l'estat: DISCONNECTED\n", time_buffer);
    if(fase_registre()) {
        time_t now = time (0);
        strftime(time_buffer, 100, "%H:%M:%S", localtime(&now));
        printf("%s: MSG. => Equip passa a l'estat: REGISTERED\n", time_buffer);
        pthread_t thread_alive, thread_comandes;
        /* Executo la funcio fase_alive() en un thread */
        pthread_create(&thread_alive, NULL, fase_alive, NULL);
        if(debug_mode) {
            time_t now = time (0);
            strftime(time_buffer, 100, "%H:%M:%S", localtime(&now));
            printf("%s: DEBUG. => Creat thread per a gestionar alives\n", time_buffer);
        }
        /* Executo la funcio fase_comandes() en un thread */
        pthread_create(&thread_comandes, NULL, fase_comandes, NULL);
        if(debug_mode) {
            time_t now = time (0);
            strftime(time_buffer, 100, "%H:%M:%S", localtime(&now));
            printf("%s: DEBUG. => Creat thread per a gestionar comandes\n", time_buffer);
        }
        /* Tanco els threads */
        pthread_join(thread_alive, NULL);
        pthread_join(thread_comandes, NULL);
        /* Tanco els sockets */
        close(socket_tcp);
        close(socket_udp);
        /* Tanco el client */
        exit(0);
    }
    else {
        printf("Error en la fase de registre");
        exit(1);
    }
    return 0;
}

/* Fase de registre */
bool fase_registre() {
    /* Inicialitzo el paquet register_req */
    register_req.tipus_paquet = 0;
    strcpy(register_req.nom_eq, nom);
    strcpy(register_req.mac_eq, mac);
    strcpy(register_req.num_aleatori, "000000");
    /* Fase de registre */
    int q=3, s=5;
    while(q>0) {
        int n=3, t=2, m=4, p=8, interval=2;
        while(p>0) {
            if(n>0) {
                sendto(socket_udp, &register_req, sizeof(struct pdu_udp), 0, (struct sockaddr *)&serverAddr_udp, sizeof(serverAddr_udp));
                if(debug_mode) {
                    time_t now = time (0);
                    strftime(time_buffer, 100, "%H:%M:%S", localtime(&now));
                    printf("%s: DEBUG. => Enviat paquet REGISTER_REQ\n", time_buffer);
                }
                recvfrom(socket_udp,&register_ack,sizeof(struct pdu_udp),0,NULL,NULL);
                if(register_ack.tipus_paquet == 0x01){
                    if(debug_mode) {
                        time_t now = time (0);
                        strftime(time_buffer, 100, "%H:%M:%S", localtime(&now));
                        printf("%s: DEBUG. => Rebut paquet REGISTER_ACK\n", time_buffer);
                    }
                    return true;
                }
                else if(register_ack.tipus_paquet == 0x02) {
                    break;
                }
                else if(register_ack.tipus_paquet == 0x03){
                    fprintf(stderr, "El registre ha estat rebutjat");
                    exit(1);
                }
                --n;
                sleep(t);
            }
            else if(n==0 && interval <= m*t) {
                sendto(socket_udp, &register_req, sizeof(struct pdu_udp), 0, (struct sockaddr *)&serverAddr_udp, sizeof(serverAddr_udp));
                recvfrom(socket_udp,&register_ack,sizeof(struct pdu_udp),0,NULL,NULL);
                if(register_ack.tipus_paquet == 0x01){
                    return true;
                }
                else if(register_ack.tipus_paquet == 0x02) {
                    break;
                }
                else if(register_ack.tipus_paquet == 0x03){
                    fprintf(stderr, "El registre ha estat rebutjat");
                    exit(1);
                }
                interval += t;
                sleep(interval);
            }
            else {
                sendto(socket_udp, &register_req, sizeof(struct pdu_udp), 0, (struct sockaddr *)&serverAddr_udp, sizeof(serverAddr_udp));
                recvfrom(socket_udp,&register_ack,sizeof(struct pdu_udp),0,NULL,NULL);
                if(register_ack.tipus_paquet == 0x01){
                    return true;
                }
                else if(register_ack.tipus_paquet == 0x02) {
                    break;
                }
                else if(register_ack.tipus_paquet == 0x03){
                    fprintf(stderr, "El registre ha estat rebutjat");
                    exit(1);
                }
                sleep(m*t);
            }
            --p;
        }
        --q;
        sleep(s);
    }
    return false;
}

/* Fase alive */
void *fase_alive() {
    inici:
    /* Inicialitzo el paquet alive_inf */
    alive_inf.tipus_paquet = 0x10;
    strcpy(alive_inf.nom_eq, nom);
    strcpy(alive_inf.mac_eq, mac);
    strcpy(alive_inf.num_aleatori, register_ack.num_aleatori);
    /* Fase alive */
    int no_alive_ack = 0;
    bool first_alive = true;
    while(1) {
        if(no_alive_ack < 3) {
            sendto(socket_udp, &alive_inf, sizeof(struct pdu_udp), 0, (struct sockaddr *)&serverAddr_udp, sizeof(serverAddr_udp));
            if(debug_mode) {
                time_t now = time (0);
                strftime(time_buffer, 100, "%H:%M:%S", localtime(&now));
                printf("%s: DEBUG. => Enviat paquet ALIVE_ACK\n", time_buffer);
            }
            recvfrom(socket_udp,&alive_ack,sizeof(struct pdu_udp),0,NULL,NULL);
            if(alive_ack.tipus_paquet == 0x11) {
                if(first_alive) {
                    time_t now = time (0);
                    strftime(time_buffer, 100, "%H:%M:%S", localtime(&now));
                    printf("%s: MSG. => Equip passa a l'estat: ALIVE\n", time_buffer);
                    first_alive = false;
                }
                if(debug_mode) {
                    time_t now = time (0);
                    strftime(time_buffer, 100, "%H:%M:%S", localtime(&now));
                    printf("%s: DEBUG. => Rebut paquet ALIVE_ACK\n", time_buffer);
                }
                no_alive_ack = 0;
            }
            else if(alive_ack.tipus_paquet == 0x12) {
                /* Do nothing */
            }
            else {
                ++no_alive_ack;
            }
        }
        else {
            break;
        }
        sleep(3);
    }
    if(fase_registre()) {
        goto inici;
    }
    else {
        printf("Error en la fase de registre");
        exit(1);
    }
}

void *fase_comandes() {
    /* Obro l'arxiu de configuració */
    FILE *boot_file = fopen(cfg_boot, "r");
    /* Guardo el nombre de bytes del fitxer cfg_boot */
    fseek(boot_file, 0, SEEK_END);
    int n_bytes = ftell(boot_file);
    fseek(boot_file, 0, SEEK_SET);
    /* Guardo la variable n_bytes en un buffer */
    char buffer[4];
    sprintf(buffer, "%d", n_bytes);
    /* Llegeixo les comandes introduides */
    char comanda[256];
    while(fscanf(stdin, "%s", comanda)) {
        /* Creo un socket TCP */
        if((socket_tcp = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            fprintf(stderr, "No puc obrir el socket\n");
            exit(1);
        }
        /* Configuro el struct d'adreçes pel socket TCP */
        int port_tcp = atoi(register_ack.dades);
        serverAddr_tcp.sin_family = AF_INET;
        serverAddr_tcp.sin_port = htons(port_tcp);
        serverAddr_tcp.sin_addr.s_addr = inet_addr("127.0.0.1");
        memset(serverAddr_tcp.sin_zero, '\0', sizeof serverAddr_tcp.sin_zero);
        /* Connecto el socket TCP al servidor */
        if (connect(socket_tcp, (struct sockaddr *)&serverAddr_tcp, sizeof(serverAddr_tcp)) < 0) { 
            printf("Error al connectar el socket TCP\n"); 
            exit(1);
        }
        /* COMANDA SEND-CONF */
        if(strcmp(comanda, "send-conf") == 0) {
            /* Inicialitzo el paquet send_file */
            send_file.tipus_paquet = 0x20;
            strcpy(send_file.nom_eq, nom);
            strcpy(send_file.mac_eq, mac);
            strcpy(send_file.num_aleatori, register_ack.num_aleatori);
            strcpy(send_file.dades, cfg_boot);
            strcat(send_file.dades, ",");
            strcat(send_file.dades, buffer);
            /* Envio el paquet send_file al servidor */
            send(socket_tcp, &send_file, sizeof(struct pdu_tcp), 0);
            read(socket_tcp,&send_ack,sizeof(struct pdu_tcp));
            /* Comprovo que el paquet rebut sigui un SEND_ACK */
            if((send_ack.tipus_paquet = 0x21)) {
                /* Inicialitzo el paquet send_data */
                send_data.tipus_paquet = 0x24;
                strcpy(send_data.nom_eq, nom);
                strcpy(send_data.mac_eq, mac);
                strcpy(send_data.num_aleatori, register_ack.num_aleatori);
                char line[150];
                /* Envio el fitxer boot_file linia per linia */
                while (fgets(line, 150, (FILE*) boot_file)) {
                    strcpy(send_data.dades, line);
                    send(socket_tcp, &send_data, sizeof(struct pdu_tcp), 0);
                    /* PROVA: Printo les dades del fitxer per la consola */
                    printf("%s\n", send_data.dades);
                }
                send_end.tipus_paquet = 0x25;
                /* Inicialitzo i envio el paquet send_end */
                strcpy(send_end.nom_eq, nom);
                strcpy(send_end.mac_eq, mac);
                strcpy(send_end.num_aleatori, register_ack.num_aleatori);
                send(socket_tcp, &send_end, sizeof(struct pdu_tcp), 0);
            }
            fclose(boot_file);
        }
        /* COMANDA GET-CONF */
        else if(strcmp(comanda, "get-conf") == 0) {
            /* Inicialitzo el paquet get_file */
            get_file.tipus_paquet = 0x30;
            strcpy(get_file.nom_eq, nom);
            strcpy(get_file.mac_eq, mac);
            strcpy(get_file.num_aleatori, register_ack.num_aleatori);
            strcpy(get_file.dades, cfg_boot);
            strcat(get_file.dades, ",");
            strcat(get_file.dades, buffer);
            /* Envio el paquet send_file al servidor */
            send(socket_tcp, &get_file, sizeof(struct pdu_tcp), 0);
            read(socket_tcp,&get_ack,sizeof(struct pdu_tcp));
            /* Comprovo que el paquet rebut sigui un get_ack */
            if(get_ack.tipus_paquet == 0x31) {
                /* Inicialitzo el paquet get_data */
                get_data.tipus_paquet = 0x34;
                strcpy(get_data.nom_eq, nom);
                strcpy(get_data.mac_eq, mac);
                strcpy(get_data.num_aleatori, register_ack.num_aleatori);
                /* Guardo el camp data dels paquets enviats pel servidor */
                read(socket_tcp,&get_data,sizeof(struct pdu_tcp));
                while(get_data.tipus_paquet != 0x35) {
                    fprintf(boot_file, "%s", get_data.dades);
                    /* PROVA: Printo les dades del fitxer per la consola */
                    printf("%s\n", get_data.dades);
                    read(socket_tcp,&get_data,sizeof(struct pdu_tcp));
                }
            }
            fclose(boot_file);
        }
        /* COMANDA QUIT */
        else if(strcmp(comanda, "quit") == 0) {
            close(socket_tcp);
            close(socket_tcp);
            exit(0);
        }
        else {
            printf("Introdueix una comanda valida\n");
        }
    }
    return 0;
}