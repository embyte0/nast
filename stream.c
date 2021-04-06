/*
    nast

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

#include "include/nast.h"

/* read data stream */

int stream (char *dev,u_long ip_src,u_long ip_dst,u_short sport,u_short dport,int lg)
{
   char errbuf[LIBNET_ERRBUF_SIZE];
   struct libnet_ipv4_hdr *ip;
   struct libnet_tcp_hdr *tcp;
   char *data;
   int n;
   u_short TCP_SIZE_H;

   if(lg)
     {
	openfile();
	printf ("Running and logging to file...\n");
     }

   fputs("NAST TCP Stream\n\n",logd);

   tm = time(NULL);
   /* per avere sia ora che data si pu usare %c, ma il compilatore tira fuori dei warning decisamente noiosi:)*/
   strftime(timed,60,"%b %d %T",localtime(&tm));

   if ((descr = pcap_open_live (dev, BUFSIZ, PROMISC, 10, errbuf)) == NULL)
     {
	w_error(1, "pcap_open_live: %s\n", errbuf);
     }

   data = malloc (1024);
   if ((offset=(device(dev,descr)))==-1) return -1;

   for (;;)
     {

	packet = (u_char *) pcap_next(descr, &hdr);
	if (packet == NULL) break;

	ip = (struct libnet_ipv4_hdr *) (packet + offset);
	if (ip->ip_p != IPPROTO_TCP) continue;

	tcp = (struct libnet_tcp_hdr *) (packet + offset + LIBNET_IPV4_H);
	TCP_SIZE_H = tcp->th_off*4;

	if ((n=ntohs(ip->ip_len) - LIBNET_IPV4_H - TCP_SIZE_H)<1) continue;

	/* caso diritto */
	if ( ip->ip_src.s_addr == ip_src && ip->ip_dst.s_addr == ip_dst && tcp->th_sport == htons(sport) && tcp->th_dport == htons(dport) )
	  {
	     fprintf(logd,"\n%s->%s\n", libnet_addr2name4(ip_src, LIBNET_RESOLVE) , libnet_addr2name4(ip_dst, LIBNET_RESOLVE));
	     data = (char *) (packet + offset + LIBNET_IPV4_H + TCP_SIZE_H);
	     data_sniffo(data, n, logd);
	  }
        /* caso rovescio */
	else if ( ip->ip_src.s_addr == ip_dst && ip->ip_dst.s_addr == ip_src && tcp->th_sport == htons(dport) && tcp->th_dport == htons(sport))
	  {
	     fprintf(logd,"\n%s<-%s\n", libnet_addr2name4(ip_src, LIBNET_RESOLVE) , libnet_addr2name4(ip_dst, LIBNET_RESOLVE));
	     data = (char *) (packet + offset + LIBNET_IPV4_H + TCP_SIZE_H);
	     data_sniffo(data, n, logd);
	  }
     }

   pcap_close(descr);

   return 0;
}

