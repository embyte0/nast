/*
    Nast common include file

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

/* include */


#include <libnet.h>
#include </usr/include/pcap.h>
#include <pthread.h>
#include "../config.h"

#ifdef HAVE_LIBNCURSES
#include <ncurses.h>
#endif

#include "ARPhdr.h"

/* colors */
#define BOLD "\033[1m"
#define UNDER "\033[3m"
#define NORMAL "\033[0m"
#define CYAN "\033[1;36m"

#define TCP_HDR_LEN  hdr.len - LIBNET_IPV4_H - LIBNET_TCP_H + offset
#define UDP_HDR_LEN hdr.len - LIBNET_IPV4_H - LIBNET_TCP_H + offset
#define ICMP_HDR_LEN hdr.len - LIBNET_IPV4_H - LIBNET_TCP_H + offset
#define IGMP_HDR_LEN hdr.len - LIBNET_IPV4_H - LIBNET_TCP_H + offset

#define PROMISC 1
#define NOT_PROMISC 0

/* sniffing functions */
int run_sniffer (u_short promisc, u_short data, u_short hex, u_short f, u_short l, u_short tcpdlog, u_short tcpdread, char *filter, char *dev, char ldname[50]);
             /* ASCII DATA,HEX DATA,LOGFILE/STDOUT,LOG DATA FILE */
void handle_TCP (u_short d, u_short x, FILE *output, FILE *ldd);
void handle_UDP (u_short d, u_short x, FILE *output, FILE *ldd);
void handle_ICMP(u_short d, u_short x, FILE *output, FILE *ldd);
void handle_IGMP(FILE *output);
void handle_ARP (FILE *output);
u_int16_t handle_ethernet (u_char *packet);

int device (char *dev, pcap_t* descr);
void data_sniffo (char *data, u_int l, FILE *log);
void print_ascii_hex (char *data_info, u_int len, FILE *log);

/* network analyzer functions */
struct host * map_lan (char *dev, u_short mode, u_short *n);
int psearch (char *dev, u_long ip_dst, u_short lg);
int fgw (u_char *dev);
int rst (char *dev, u_long src, u_long dst, u_short sport, u_short dport);
int flink (u_char *dev);
int port(char *dev, u_long dst_ip, libnet_plist_t *plist_p, int lg);
int mport (u_char *dev, u_short ports[], int lg);
int mhport (u_char *dev, libnet_plist_t *plist_p, int lg);
int stream (char *dev, u_long ip_src, u_long ip_dst, u_short sport, u_short dport, int lg);
int car (char *dev, int lg);
int run_bc (char *dev, char *filter);

/* other functions*/
void sigexit();
void openfile(void);
void bkg(void);

/* ncurses menu */
#ifdef HAVE_LIBNCURSES
int main_graph(void);
#endif

/* common functions */
char * dn (char * s);
int runcplx (char what, char *dev, int l);
char * nast_hex_ntoa (u_char *s);
char * nast_atoda (u_char *s);
int w_error(int fatal, char *err, ...);
int n_error(char *err, int fatal);
void n_print(char *wins, int y, int x, int lg, char *string, ...);
int ng_print(char *wins, int y, int x, char *string);
int check_pthread(void);
void init_scr(void);

/* variable */
FILE *logd;
short offset;
int npkt;
u_char *packet;
u_char *buf;
struct pcap_pkthdr hdr;
pcap_t* descr;
pcap_dumper_t *dumper;
struct pcap_stat statistic;
bpf_u_int32 maskp;          /* subnet mask               */
bpf_u_int32 netp;  	    /* ip                        */
int datalink;
struct bpf_program fp;      /* hold compiled program     */
char *logname;
char *tcpdl;
u_short tr,tl;
u_short graph;              /* global var for ncurses mode */
u_short cont;
/* golbal var*/
int stream_glob;
int bc_glob;
int sniff_glob;
int rst_glob;
int arp_glob;
pthread_t pt[2];
int lg;

struct host
{
   unsigned char mac[ETHER_ADDR_LEN];
   unsigned char ip[4];
};

/* time variable */
time_t tm;
char timed[60];

/* for demonize nast */
u_short demonize;

int line_s;
int row_s;


