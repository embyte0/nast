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

/* handle a tcp packet */
void handle_TCP (u_short d, u_short x, FILE *output, FILE *ldd)
{
   struct libnet_ipv4_hdr *ip;
   struct libnet_tcp_hdr *tcp;
   struct servent *service;
   u_char flags;
   u_short size_ip, size_tcp, size_buf;


   size_ip = LIBNET_IPV4_H;
   size_buf = 0;
   buf = NULL;

   ip = (struct libnet_ipv4_hdr *) (packet+offset);
   tcp = (struct libnet_tcp_hdr *) (packet+size_ip+offset);

   size_tcp = (tcp->th_off) * 4;

   n_print("princ",line_s,row_s,lg,"\n---[ TCP ]-----------------------------------------------------------\n");
   service = getservbyport(htons(ntohs(tcp->th_sport)), "tcp");
   n_print("princ",line_s=line_s+2,row_s,lg,"%s:%d(%s)",inet_ntoa(ip->ip_src),ntohs(tcp->th_sport),(service) ? service->s_name : "unknown");
   service = getservbyport(htons(ntohs(tcp->th_dport)), "tcp");
   n_print("princ",line_s,28,lg," -> ");
   n_print("princ",line_s,33,lg,"%s:%d(%s)\n",inet_ntoa(ip->ip_dst),ntohs(tcp->th_dport),(service) ? service->s_name : "unknown");
   n_print("princ",++line_s,row_s,lg,"TTL: %d \t", ip->ip_ttl);
   n_print("princ",line_s,10,lg,"Window: %d\t", ntohs(tcp->th_win));
   n_print("princ",line_s,25,lg,"Version: %d\t", ip->ip_v);
   n_print("princ",line_s,39,lg,"Lenght: %d\n", ntohs(ip->ip_len));
   n_print("princ",++line_s,row_s,lg,"FLAGS: ");

   /*modifed by embyte */
   flags = tcp->th_flags;
   row_s = 8;

   if (flags & TH_FIN)  /*se mascherando con il fin ottengo 1 vuol dire che c�(l'and �1 se tutti e due sono 1) */
     n_print("princ",line_s,++row_s,lg,"F");
   else
     n_print("princ",line_s,++row_s,lg,"-");
   if (flags & TH_SYN)
     n_print("princ",line_s,++row_s,lg,"S");
   else
     n_print("princ",line_s,++row_s,lg,"-");
   if (flags & TH_RST)
     n_print("princ",line_s,++row_s,lg,"R");
   else
     n_print("princ",line_s,++row_s,lg,"-");
   if (flags & TH_PUSH)
     n_print("princ",line_s,++row_s,lg,"P");
   else
     n_print("princ",line_s,++row_s,lg,"-");
   if (flags & TH_ACK)
     n_print("princ",line_s,++row_s,lg,"A");
   else
     n_print("princ",line_s,++row_s,lg,"-");
   if (flags & TH_URG)
     n_print("princ",line_s,++row_s,lg,"U");
   else
     n_print("princ",line_s,++row_s,lg,"-");
   if (flags & 0x80)
     n_print("princ",line_s,++row_s,lg,"U");
   else
     n_print("princ",line_s,++row_s,lg,"-");
   if (flags & 0x40)
     n_print("princ",line_s,++row_s,lg,"E");

   n_print("princ",line_s,16,lg,"\tSEQ: %u - ACK: %u\n", ntohl(tcp->th_seq),ntohl(tcp->th_ack));
   n_print("princ",++line_s,0,lg,"Packet Number: %d",npkt);

   if(!graph)
   	printf("\n");
   row_s=0;
   ++line_s;


   size_buf = ntohs(ip->ip_len) - size_ip - size_tcp;

   if (size_buf)
     {
	buf = (char *) (packet + offset + size_ip + size_tcp);

	if (d)
	  {
	     n_print("princ",line_s,row_s,lg,"\n---[ TCP Data ]------------------------------------------------------\n");
	     data_sniffo (buf, size_buf, output);
	  }

	if (x)
	  {
	     n_print("princ",line_s,row_s,lg,"\n---[ TCP Hex-Ascii Data ]--------------------------------------------");
	     print_ascii_hex (buf, size_buf, output);
	  }

        /* log data (payload only) */
	if (ldd)
	  {

	     service = getservbyport(htons(ntohs(tcp->th_sport)), "tcp");
	     fprintf(ldd, "%s:%d(%s) -> ",inet_ntoa(ip->ip_src),ntohs(tcp->th_sport),(service) ? service->s_name : "unknown");
	     service = getservbyport(htons(ntohs(tcp->th_dport)), "tcp");
	     fprintf(ldd, "%s:%d(%s) TCP\n",inet_ntoa(ip->ip_dst),ntohs(tcp->th_dport),(service) ? service->s_name : "unknown");

	     data_sniffo (buf, size_buf, ldd);
	     fprintf(ldd, "\n");

	  }
     }
   row_s = 0;
}
