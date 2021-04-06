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

void handle_IGMP (FILE *output)
{
   struct libnet_ipv4_hdr *ip;
   struct libnet_igmp_hdr *igmp;

   ip = (struct libnet_ipv4_hdr *) (packet + offset);
   igmp = (struct libnet_igmp_hdr *) (packet + LIBNET_IPV4_H + offset);

   n_print("princ",line_s,row_s,lg,"\n---[ IGMP ]----------------------------------------------------------\n");
   n_print("princ",line_s=line_s+2,row_s,lg,"%s -> %s\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
   n_print("princ",++line_s,row_s,lg,"IP Version: %d\t Lenght: %d\t", ip->ip_v, ntohs(ip->ip_len));
   n_print("princ",line_s,30,lg,"TTL: %d\t Code: %d\n", ip->ip_ttl, igmp->igmp_code);
   n_print("princ",++line_s,row_s,lg,"Type: ");

   switch(igmp->igmp_type)
     {
      case 0x11:
	n_print("princ",line_s,10,lg,"Membreship Query v1 [get address %s]\n", inet_ntoa(igmp->igmp_group));
	break;
      case 0x12:
	n_print("princ",line_s,10,lg,"Membership Report v1  %s\n", inet_ntoa(igmp->igmp_group));
	break;
      case 0x16:
	n_print("princ",line_s,10,lg,"Membership Report v2  %s\n", inet_ntoa(igmp->igmp_group));
	break;
      case 0x17:
	n_print("princ",line_s,10,lg,"Leave %s (v2)\n", inet_ntoa(igmp->igmp_group));
	break;
      default:
	n_print("princ",line_s,10,lg,"%d\n", igmp->igmp_type);
	break;
     }
   n_print("princ",++line_s,0,lg,"Packet Number: %d",npkt);

   if(!graph)
   	printf("\n");

   row_s=0;
   ++line_s;
}

