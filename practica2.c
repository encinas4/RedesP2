/***************************************************************************
 practica2.c
 Muestra las direciones Ethernet de la traza que se pasa como primer parametro.
 Debe complatarse con mas campos de niveles 2, 3, y 4 tal como se pida en el enunciado.
 Debe tener capacidad de dejar de analizar paquetes de acuerdo a un filtro.

 Compila: gcc -Wall -o practica2 practica2.c -lpcap, make
 Autor: Jose Luis Garcia Dorado, Jorge E. Lopez de Vergara Mendez, Rafael Leira, Javier Ramos
 2018 EPS-UAM
***************************************************************************/
#include "practica2.h"

void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack);
void handleSignal(int nsignal);

pcap_t *descr = NULL;
uint64_t contador = 0;
uint8_t ipsrc_filter[IP_ALEN] = {NO_FILTER};
uint8_t ipdst_filter[IP_ALEN] = {NO_FILTER};
uint16_t sport_filter= NO_FILTER;
uint16_t dport_filter = NO_FILTER;


void handleSignal(int nsignal){
	(void) nsignal; // indicamos al compilador que no nos importa que nsignal no se utilice

	printf("Control C pulsado\n");
	pcap_breakloop(descr);
}

int main(int argc, char **argv){
	char errbuf[PCAP_ERRBUF_SIZE];

	int long_index = 0, retorno = 0;
	char opt;

	(void) errbuf; //indicamos al compilador que no nos importa que errbuf no se utilice. Esta linea debe ser eliminada en la entrega final.

	if (signal(SIGINT, handleSignal) == SIG_ERR) {
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	if (argc == 1) {
		printf("Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]\n", argv[0]);
		exit(ERROR);
	}

	static struct option options[] = {
		{"f", required_argument, 0, 'f'},
		{"i",required_argument, 0,'i'},
		{"ipo", required_argument, 0, '1'},
		{"ipd", required_argument, 0, '2'},
		{"po", required_argument, 0, '3'},
		{"pd", required_argument, 0, '4'},
		{"h", no_argument, 0, '5'},
		{0, 0, 0, 0}
	};

	//Simple lectura por parametros por completar casos de error, ojo no cumple 100% los requisitos del enunciado!
	while( (opt = getopt_long_only(argc, argv, "f:i:1:2:3:4:5", options, &long_index)) != -1){
		switch( opt ){
		case 'i' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}
			
			/* abrimos la interfaz */
			if ( (descr = pcap_open_live(optarg, *argv[1], 1, 100, errbuf)) == NULL){
				printf("Error: pcap_open_live(): Interface: %s, %s %s %d.\n", optarg,errbuf,__FILE__,__LINE__);
				exit(ERROR);
			}

			break;

		case 'f' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}

			/* Abrimos la traza */
			if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
				printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
				exit(ERROR);
			}

			break;


		case '1' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipsrc_filter[0]), &(ipsrc_filter[1]), &(ipsrc_filter[2]), &(ipsrc_filter[3])) != IP_ALEN) {
				printf("Error ipo_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '2' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipdst_filter[0]), &(ipdst_filter[1]), &(ipdst_filter[2]), &(ipdst_filter[3])) != IP_ALEN) {
				printf("Error ipd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '3' :
			if ((sport_filter= atoi(optarg)) == 0) {
				printf("Error po_filtro.Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '4' :
			if ((dport_filter = atoi(optarg)) == 0) {
				printf("Error pd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '5' :
			printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;

		case '?' :
		default:
			printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;
		}
	}

	if (!descr) {
		printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}

	//Simple comprobacion de la correcion de la lectura de parametros
	printf("Filtro:");
	//if(ipsrc_filter[0]!=0)
	printf("ipsrc_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipsrc_filter[0], ipsrc_filter[1], ipsrc_filter[2], ipsrc_filter[3]);
	//if(ipdst_filter[0]!=0)
	printf("ipdst_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipdst_filter[0], ipdst_filter[1], ipdst_filter[2], ipdst_filter[3]);

	if (sport_filter!= NO_FILTER) {
		printf("po_filtro=%"PRIu16"\t", sport_filter);
	}

	if (dport_filter != NO_FILTER) {
		printf("pd_filtro=%"PRIu16"\t", dport_filter);
	}

	printf("\n\n");

	retorno=pcap_loop(descr,NO_LIMIT,analizar_paquete,NULL);
	switch(retorno)	{
		case OK:
			printf("Traza leída\n");
			break;
		case PACK_ERR:
			printf("Error leyendo paquetes\n");
			break;
		case BREAKLOOP:
			printf("pcap_breakloop llamado\n");
			break;
	}
	printf("Se procesaron %"PRIu64" paquetes.\n\n", contador);
	pcap_close(descr);
	return OK;
}


void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack){
	(void)user;
	printf("\nNuevo paquete capturado el %s\n", ctime((const time_t *) & (hdr->ts.tv_sec)));
	contador++;
	int i = 0;
	char protocAux[5];
	char protocAux2[5];
	uint16_t memcpyAux;
	uint8_t ihl, protocolo;
	uint8_t ipsrc_filter_aux[IP_ALEN] = {NO_FILTER};
	/*uint8_t ipdst_filter_aux[IP_ALEN] = {NO_FILTER};
	uint16_t sport_filter_aux = NO_FILTER;
	uint16_t dport_filter_aux = NO_FILTER;*/


	/* Se imprime la direccion de enlace de destino*/
	printf("Direccion ETH destino= ");
	printf("%02X", pack[0]);
	for (i = 1; i < ETH_ALEN; i++) {
		printf("-%02X", pack[i]);
	}
	printf("\n");
	
	pack += ETH_ALEN;

	/* Se imprime la direccíon de enlace de origen*/
	printf("Direccion ETH origen = ");
	printf("%02X", pack[0]);
	for (i = 1; i < ETH_ALEN; i++) {
		printf("-%02X", pack[i]);
	}
	printf("\n");

	/* Se imprime el tipo de protocolo */
	pack+=ETH_ALEN;
	printf("Tipo de protocolo encapsulado = ");
	for (i=0; i < ETH_TLEN; i++){
		printf("%02X", pack[i]);
	}
	printf("\n");

	/* Comprobamos si es IPv4 ayundandonos de dos strings */
	sprintf(protocAux,"%02X",pack[0]);
	sprintf(protocAux2, "%02X",pack[1]);
	strcat(protocAux,protocAux2);
	
	/* Si es IPv4 deja de imprimir campos*/
	if(strcmp(protocAux,"0800")!=0){
		printf("El protocolo encapsulado no es IPv4.\n");
		return;
	}


	/* Imprimimos campos de nivel 3 */
	/* Se imprime la version */
	pack+=ETH_TLEN;
	printf("Version IP: %d\n", pack[0]>>4);
	ihl = pack[0] & 0b00001111;
	ihl *= 4;

	/* Se imprime la longitud de cabecera */
	printf("Longitud de la cabecera: %d(%d)\n", pack[0] & 0b00001111, ihl);

	/* Se imprime la longitud total */
	if( memcpy(&memcpyAux,  &pack[2], sizeof(uint16_t)) == NULL ){
		printf("Fallo copia de memoria para memcpyAux en longitud total .\n");
		return;
	}
	printf("Longitud Total: %d \n", ntohs(memcpyAux) );

	pack+=IP_ALEN;

	/* Se imprime el desplazamiento */
	if( memcpy(&memcpyAux,  &pack[2], sizeof(uint16_t)) == NULL ){
		printf("Fallo copia de memoria para memcpyAux en desplazamiento .\n");
		return;
	}
	memcpyAux = ntohs(memcpyAux) & 0b0001111111111111;
	printf("Desplazamiento: %d \n", memcpyAux );
	if( memcpyAux != 0 ){
		printf("Dado que el desplazamiento es distinto de 0 no analizaremos los campos del siguiente nivel\n");
		return;
	}

	pack+=IP_ALEN;

	/* Se imprime la tiempo de vida */
	printf("Tiempo de vida: %d \n", pack[0]);

	/* Se imprime protocolo */
	protocolo = pack[1];
	printf("Protocolo: %d \n", protocolo );
	if( pack[1]!=17 && pack[1]!=6 ){
		printf("El protocolo no es ni UDP ni TCP con lo que los siguientes niveles no seran analizados.\n");
		return;
	}

	pack+=IP_ALEN;

	/* Se guarda la ip origen que se va a comparar con la ip origen del filtro*/
	ipsrc_filter_aux[0]=pack[0];
	for (i = 1; i < IP_ALEN; i++) {
		ipsrc_filter_aux[i] = pack[i];
	}

	/* Se imprime la direcciones ip(origen y dest) formato 192.168.1.0 si coincide con el filtro o no hay*/
	if( ipsrc_filter[0] != 0 && ipsrc_filter[1] != 0 && ipsrc_filter[2] != 0 && ipsrc_filter[3] != 0) {
		if(ipsrc_filter[0] != ipsrc_filter_aux[0] || ipsrc_filter[1] != ipsrc_filter_aux[1] || ipsrc_filter[2] != ipsrc_filter_aux[2] || ipsrc_filter[3] != ipsrc_filter_aux[3]){
			printf("Las ip de origen no coincide con la ip origen del filtro\n");
			return;
		}
	}

	printf("Direccion IP origen = ");
	printf("%d", pack[0]);
	for (i = 1; i < IP_ALEN; i++) {
		printf(".%d", pack[i]);
	}
	printf("\n");

	pack+=IP_ALEN;
	printf("Direccion IP destino = ");
	printf("%d", pack[0]);
	for (i = 1; i < IP_ALEN; i++) {
		printf(".%d", pack[i]);
	}
	printf("\n");

	/* Imprimimos los campos del nivel 4 */
	if( ihl-IP_ALEN*5 == 0 ){
		/* el campo opciones y relleno no estan presentes en el paquete*/
		pack+=IP_ALEN;
	}else{
		pack+=IP_ALEN*2;
	}

	/* se imprime el numero de puerto de origen y puerto de destino */
	if( memcpy(&memcpyAux,  &pack[0], sizeof(uint16_t)) == NULL ){
		printf("Fallo copia de memoria para memcpyAux en nivel 4 .\n");
		return;
	}
	printf("puerto origen : %d \n", ntohs(memcpyAux) );

	if( memcpy(&memcpyAux,  &pack[2], sizeof(uint16_t)) == NULL ){
		printf("Fallo copia de memoria para memcpyAux en nivel 4 .\n");
		return;
	}
	printf("puerto destino : %d \n", ntohs(memcpyAux) );

	pack+=IP_ALEN;

	if( protocolo == 6 ){	/* caso TCP */
		/* mostrar los valores de las banderas SYN y FIN */
		pack+=IP_ALEN*2;
		if( (pack[1] & 0b00000010)== 2){
			printf("SYN: 1\n");	
		}else{
			printf("SYN: 0\n");	
		}

		printf("FIN: %d\n", pack[1] & 0b00000001);

	}else{	/* caso UDP */
		/*Mostrar el campo longitud*/
		if( memcpy(&memcpyAux,  &pack[0], sizeof(uint16_t)) == NULL ){
			printf("Fallo copia de memoria para memcpyAux en nivel 4 .\n");
			return;
		}
		printf("Longitud: %d\n", ntohs(memcpyAux));
	}
}
