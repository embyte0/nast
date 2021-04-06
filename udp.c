/*
    nast

    Copyright (C) 2002  Snifth

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

/* handle a udp packet */
void handle_UDP (u_short d, u_short x, FILE *output, FILE *ldd)
{
   struct libnet_ipv4_hdr *ip;
   struct libnet_udp_hdr *udp;
   struct servent *service;
   u_short size_buf, size_ip, size_udp;


   size_ip = LIBNET_IPV4_H;
   size_udp = LIBNET_UDP_H;
   size_buf = 0;

   ip = (struct libnet_ipv4_hdr *) (packet+offset);
   udp = (struct libnet_udp_hdr *) (packet+size_ip+offset);

   service = getservbyport (htons(ntohs(udp->uh_sport)), "udp");
   n_print("princ",line_s,row_s,lg,"\n---[ UDP ]-----------------------------------------------------------\n");
   n_print("princ",line_s=line_s+2,row_s,lg,"%s:%d(%s)", inet_ntoa (ip->ip_src), ntohs(udp->uh_sport), (service) ? service->s_name : "unknown");
   service = getservbyport(htons(ntohs(udp->uh_dport)), "udp");
   n_print("princ",line_s,28,lg," -> ");
   n_print("princ",line_s,33,lg,"%s:%d(%s)\n", inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport), (service) ? service->s_name : "unknown");
   n_print("princ",++line_s,row_s,lg,"Version: %d\t Total Lenght: %d\t", ip->ip_v, ntohs(ip->ip_len));
   n_print("princ",line_s,39,lg, "TTL: %d\n", ip->ip_ttl); 
   n_print("princ",++line_s,0,lg,"Packet Number: %d",npkt);

   if(!graph)
   	printf("\n");

   size_buf = ntohs(ip->ip_len) - size_ip - size_udp;
   ++line_s;
   row_s=0;
   /* there is a payload */
   if (size_buf)
     {
	buf = (char *) (packet + size_ip + size_udp + offset);

	if (d)
	  {
	     n_print("princ",line_s,row_s,lg,"\n---[ UDP Data ]------------------------------------------------------\n");
	     data_sniffo (buf, size_buf, output);
	  }

	if (x)
	  {
	     n_print("princ",line_s,row_s,lg,"\n---[ UDP Hex-Ascii Data ]--------------------------------------------");
	     print_ascii_hex (buf, size_buf, output);
	  }

        /* log data (payload only) */
	if (ldd)
	  {
	     service = getservbyport (htons(ntohs(udp->uh_sport)), "udp");
	     fprintf(ldd, "%s:%d(%s) -> ", inet_ntoa (ip->ip_src), ntohs(udp->uh_sport), (service) ? service->s_name : "unknown");
	     service = getservbyport(htons(ntohs(udp->uh_dport)), "udp");
	     fprintf(ldd, "%s:%d(%s) UDP\n", inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport), (service) ? service->s_name : "unknown");

	     data_sniffo (buf, size_buf, ldd);
	     fprintf(ldd, "\n");

	  }
     }
   row_s=0;

}

