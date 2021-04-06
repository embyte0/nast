/*
    Nast

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

void handle_ARP (FILE *output)
{
   struct nast_arp_hdr *arp;
   struct libnet_ethernet_hdr *eptr;
   u_short ether_type;

   eptr = (struct libnet_ethernet_hdr *) packet;
   arp = (struct nast_arp_hdr *) (packet+offset);
   ether_type = ntohs(eptr->ether_type);

   if (ether_type == ETHERTYPE_ARP)
     {
	n_print("princ",line_s,row_s,lg,"\n---[ ARP ]-----------------------------------------------------------\n");
	n_print("princ",line_s=line_s+2,row_s,lg,"%s", nast_hex_ntoa (eptr->ether_shost));
	n_print("princ",line_s,28,lg," -> ");
	n_print("princ",line_s,33,lg, "%s\n", nast_hex_ntoa (eptr->ether_dhost));

	switch (ntohs(arp->ar_op))
	  {
	   case 1:
	       {
		  n_print("princ",++line_s,row_s,lg,"Type: ARP request: ");
		  n_print("princ",line_s,20,lg,"Who has %d.%d.%d.%d? ",arp->__ar_tip[0],arp->__ar_tip[1],arp->__ar_tip[2],arp->__ar_tip[3]);
		  n_print("princ",line_s,46,lg,"Tell %d.%d.%d.%d\n",arp->__ar_sip[0],arp->__ar_sip[1],arp->__ar_sip[2],arp->__ar_sip[3]);
	       }
	     break;
	   case 2:
	       {
		  n_print("princ",++line_s,row_s,lg,"Type: ARP reply: ");
		  n_print("princ",line_s,20,lg,"%d.%d.%d.%d is at %s\n",arp->__ar_sip[0],arp->__ar_sip[1],arp->__ar_sip[2],arp->__ar_sip[3], nast_hex_ntoa (eptr->ether_shost));
	       }
	     break;
	   case 8:
	     n_print("princ",++line_s,row_s,lg,"Type: InARP request");
	     break;
	   case 9:
	     n_print("princ",++line_s,row_s,lg,"Type: InARP reply");
	     break;
	   default:
	     n_print("princ",++line_s,row_s,lg,"Type: Unknown Opcode");
	     break;
	  }

	n_print("princ",++line_s,row_s,lg,"Hardware size: %d - ", arp->ar_hln);
	n_print("princ",line_s,30,lg,"Protocol size: %d\n", arp->ar_pln);

     }

   else  if (eptr->ether_type == ETHERTYPE_REVARP)
     {
	n_print("princ",line_s,row_s,lg,"\n---[ RARP ]----------------------------------------------------------\n");
	n_print("princ",line_s=line_s+2,row_s,lg,"%s" , nast_hex_ntoa (eptr->ether_shost));
	n_print("princ",line_s,28,lg," -> ");
	n_print("princ",line_s,33,lg,"%s\n", nast_hex_ntoa (eptr->ether_dhost));
	switch (ntohs(arp->ar_op))
	  {
	   case 3:
	     n_print("princ",++line_s,row_s,lg,"Type: RARP request");
	     break;
	   case 4:
	     n_print("princ",++line_s,row_s,lg,"Type: RARP reply");
	     break;
	   case 8:
	     n_print("princ",++line_s,row_s,lg,"Type: InARP request");
	     break;
	   case 9:
	     n_print("princ",++line_s,row_s,lg,"Type: InARP reply");
	     break;
	   default:
	     n_print("princ",++line_s,row_s,lg,"Type: Unknown Opcode");
	     break;

	  }

	n_print("princ",++line_s,row_s,lg,"Hardware size: %d  ",arp->ar_hln);
	n_print("princ",++line_s,30,lg,"Protocol size: %d\n",arp->ar_pln);

     }
   n_print("princ",++line_s,0,lg,"Packet Number: %d",npkt);

   if(!graph)
   	printf("\n");
   ++line_s;
   row_s=0;
}

/* This function is important: control ARP response and verify that no-one is making arp-poisoning in LAN
 * NB_ It's important that you run this function when U are sure that no-one is making arp-poisoning, so I can
 * retrive a truly ip-mac list to confront the next ARP response with
 *
 * PS: ARP_RESPONSE have not broadcast destination like REQUEST
 */

/* car : control arp response */
int car (char *dev,int lg)
{
   struct host *list;
   u_short i,n;
   char ebuf[PCAP_ERRBUF_SIZE];
   struct nast_arp_hdr *arp;
   int line;

   line=6;

#ifdef HAVE_LIBNCURSES
   if (graph)
     init_scr();
#endif

   if (lg)
     {
	openfile();
	n_print (NULL,0,0,lg,"Logging to file... \n");
	fflush (stdout);
        n_print (NULL,0,0,lg,"NAST Control ARP Poisoning Report\n\n");
	n_print (NULL,0,0,lg,"Made on %s\n\n", timed);
     }

   list = malloc (sizeof (struct host) * 255); /* to implement like list */

   n_print ("princ",1,1,lg,"I'll build a truly MAC-IP list...\n\n");
   n_print ("princ",2,1,lg,"(Press a key)\n");
   getchar();
   n_print ("princ",3,1,lg,"- Waiting please... \n");
   fflush (stdout);

   if ((list = map_lan(dev, 0, &n))==NULL)
     {
	if(w_error(0, "\nCan't build truly host list! mmhhh!\nReport bug to author please\n\n")==-1)
		return(1);
     }
   if (n==0)
     {
	if(w_error(0, "What are you doing? You are alone in this network!\n")==-1)
		return(1);
     }

   n_print ("princ",4,1,lg,"- Now let me sniff arp-response on the network...\n\n");

   /* open pcap sniffer */
   if ((pcap_lookupnet(dev, &netp, &maskp, ebuf))==-1)
     {
	w_error(1, "pcap_lookupnet error: %s\n", ebuf);
     }
   if ((descr = pcap_open_live(dev, BUFSIZ, PROMISC, 10, ebuf))==NULL)
     {
	w_error(1, "pcap_open_live error: %s\n", ebuf);
     }
   if ((pcap_compile (descr, &fp, "arp", 0, netp))==-1)
     {
	w_error(1, "pcap_compile error\n");
     }
   if ((pcap_setfilter (descr, &fp))==-1)
     {
	w_error(1, "pcap_setfilter error\n");
     }

   /* demonize */
   if (demonize)
     bkg();

   /* now sniff */
   while (1)
     {	
	if ((packet = (u_char *) pcap_next (descr, &hdr))==NULL) continue;

       	if (handle_ethernet(packet)!=ETHERTYPE_ARP) continue; /* this is a paranoic test */
	arp = (struct nast_arp_hdr *) (packet+offset);
	
	if (ntohs (arp->ar_op)==2)
	  {
	     for (i=0; i<n; i++)
	       {
	          /* ricerco nel db l'ip di interesse (i) */
		  if (!memcmp(arp->__ar_sip, list[i].ip, 4))
		    {
		       n_print ("princ",line,1,lg,"Verifing: %d.%d.%d.%d ", arp->__ar_sip[0], arp->__ar_sip[1], arp->__ar_sip[2], arp->__ar_sip[3]);
		       n_print ("princ",line,27,lg,"Is %s ?\t", nast_hex_ntoa(arp->__ar_sha));

		       if (memcmp(arp->__ar_sha, list[i].mac, ETHER_ADDR_LEN))
			 n_print ("princ",line,40,lg,"Warning! Truly is %s, possible ARP-Poisoning!!!\n", nast_hex_ntoa (list[i].mac));
		       else
			 n_print ("princ",line,40,lg,"Correct\n");

		       ++line;

		       break;
		    }
	       }
	  }
     }

   if (lg) n_print (NULL,0,0,lg,"\ndone\n");
   return 0;
}
