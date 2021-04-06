/*
    Nast - map.c

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

/* pseudo BuG : If someone is arp-poisoning we must him as the owner of the ip!

------

 * This function receive 1 if it must print to stdout (nast -m)
 * alse 0 if is used by another funz (run in silent mode)
 *
 *
 * Return if called from another function:
 * - NULL on error
 * - n=0 if localhost is the only host in network segment
 * - n>0 and struct host
 */

/* Don't touch here said embyte */

#include "include/nast.h"

int arpreply (u_char *t, char *dev, u_short mode, int lg);
int send_arp(libnet_t *l, u_char *device, u_char *ip_dst, u_char *enet_src, u_long ip_src);
struct host * map_lan(char *dev, u_short mode, u_short * n);
u_int scan_ulong(char *s, u_long *u);

int line;

u_char enet_dst[6] =        /* broadcast */
{
   0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

u_short k, count;
struct host * uphost;
char errbuf[256];
libnet_ptag_t ptag;

struct host * map_lan(char *dev, u_short mode, u_short * n)
{
   libnet_t *l;
   struct libnet_ether_addr *e;
   struct in_addr addr;
   char r[3];
   long ip_src;
   u_long u;
   u_int i;
   u_char ip_dst[4], orig_ip[4];
   u_char netmask[4], enet_src[6], offset[4];
   char *net, *mask;
   u_short j[4]; /* index */


   count=k=ptag=0;
   line = 7;

#ifdef HAVE_LIBNCURSES
   if(graph && mode)
     init_scr();
#endif

   /* make uphost point to at least 1 cell to avoid conflict with NULL on error */
   uphost = calloc (1, sizeof (struct host));

   if (demonize && mode)
     {
	w_error(0,"Is very useless demonize me in mapping LAN! Omit");
	demonize=0;
     }

   if ((l = libnet_init (LIBNET_LINK, dev, errbuf))==NULL)
     {
	w_error(1, "libnet_init() : %s\n", errbuf);
     }

   if ((e = libnet_get_hwaddr(l))==NULL)
     {
	w_error(1, "Can't get hardware address: %s\n", errbuf);
     }

   memcpy (enet_src, e->ether_addr_octet, 6);

   if((ip_src = libnet_get_ipaddr4(l))==-1)
     {
	w_error(1, "Error getting ip source\n");
     }

   if (pcap_lookupnet(dev, &netp, &maskp, errbuf)==-1)
     {
	w_error(1, "Error: %s\n", errbuf);
     }

   addr.s_addr = netp;
   if ((net = inet_ntoa(addr))==NULL)
     {
	w_error(1, "Impossible get the netaddress\n");
     }

   /* netaddress */
   i = scan_ulong(net,&u); if (!i) return NULL; ip_dst[0] = u; net += i;
   if (*net != '.') return NULL; ++net;
   i = scan_ulong(net,&u); if (!i) return NULL; ip_dst[1] = u; net += i;
   if (*net != '.') return NULL; ++net;
   i = scan_ulong(net,&u); if (!i) return NULL; ip_dst[2] = u; net += i;
   if (*net != '.') return NULL; ++net;
   i = scan_ulong(net,&u); if (!i) return NULL; ip_dst[3] = u; net += i;

   memcpy (orig_ip, ip_dst, 4);

   addr.s_addr = maskp;
   if ((mask = inet_ntoa(addr))==NULL)
     {
	w_error(1, "Impossible get the netmask\n");
     }

   /* netmask */
   i = scan_ulong(mask,&u); if (!i) return NULL; netmask[0] = u; mask += i;
   if (*mask != '.') return NULL; ++mask;
   i = scan_ulong(mask,&u); if (!i) return NULL; netmask[1] = u; mask += i;
   if (*mask != '.') return NULL; ++mask;
   i = scan_ulong(mask,&u); if (!i) return NULL; netmask[2] = u; mask += i;
   if (*mask != '.') return NULL; ++mask;
   i = scan_ulong(mask,&u); if (!i) return NULL; netmask[3] = u; mask += i;

   /* computate offset from netaddress and netmask */
   for (i=0; i<=3; i++)     offset[i]=255-netmask[i];

   /* large netmask */
   if (offset[1] && offset[2] && offset[3])
     {
	if (mode)
	  {
	     n_print ("winfo",1,2,lg,"You are going to scan a large network (%s netmask)! Are you sure? (y/n) : ", nast_atoda(netmask));
	     fgets(r, 3, stdin);
	     if (!(r[0]=='s' || r[0]=='S' || r[0]=='y' || r[0]=='Y')) goto refuse;
	     printf ("\n");
	  }
	else
	  n_print ("winfo",2,2,lg,"Warning, scanning a large netmask (%s), this will take a long time\n", nast_atoda(netmask));
     }

   /* begin to map */
   if (mode)
     {
	n_print("princ",1,1,lg,"Mapping the Lan for %s subnet ... please wait\n\n", nast_atoda(netmask));
	n_print("princ",3,1,lg,"MAC address\t\tIp address (hostname)\n");
	n_print("princ",4,1,lg,"===========================================================\n");
     }

   /* print il localhost */
   if (mode)
     {
	n_print ("princ",6,1,lg,"%s\t", nast_hex_ntoa (e->ether_addr_octet));
	n_print ("princ",6,24,lg,"%s (%s) (*)\n",libnet_addr2name4(ip_src , 0),libnet_addr2name4(ip_src , LIBNET_RESOLVE));
     }

   /* open descriptor to read */
   if ((descr = pcap_open_live (dev, BUFSIZ, NOT_PROMISC, 10, errbuf))==NULL)
     {

	w_error(1, "pcap_open_live() error : %s\n", errbuf);
     }

   /* put filter on arp */
   if(pcap_compile(descr, &fp, "arp", 0, netp) == -1)
     {
	w_error(1,"Error calling pcap_compile\n\n");
     }
   if(pcap_setfilter(descr, &fp) == -1)
     {
	w_error(1, "Error calling pcap_setfilter\n\n");
     }

   /* begin! */

   /* don't arp request subnet ip */
   ip_dst[3]++;

   /* 255.255.255.XXX */
   if (!offset[0] && !offset[1] && !offset[2] && offset[3])
     for (j[3]=0; j[3]<=offset[3]; j[3]++)
       {
	  if (send_arp(l, dev, ip_dst, enet_src, ip_src)==-1) goto error;
	  arpreply(ip_dst, dev, mode, lg);
	  ip_dst[3]++;
       }
   /* 255.255.XXX.XXX */
   else if (!offset[0] && !offset[1] && offset[2] && offset[3])
     for (j[2]=0; j[2]<=offset[2]; j[2]++)
       {
	  for (j[3]=0; j[3]<=offset[3]; j[3]++)
	    {
	       if (send_arp(l, dev, ip_dst, enet_src, ip_src)==-1) goto error;
	       arpreply(ip_dst, dev, mode, lg);
	       ip_dst[3]++;
	    }
	  ip_dst[2]++;
	  ip_dst[3]=orig_ip[3];
       }
   /* 255.XXX.XXX.XXX */
   else if (!offset[0] && offset[1] && offset[2] && offset[3])
     {
	for (j[1]=0; j[1]<=offset[1]; j[1]++)
	  {
	     for (j[2]=0; j[2]<=offset[2]; j[2]++)
	       {
		  for (j[3]=0; j[3]<=offset[3]; j[3]++)
		    {
		       if (send_arp(l, dev, ip_dst, enet_src, ip_src)==-1) goto error;
		       arpreply(ip_dst, dev, mode, lg);
		       ip_dst[3]++;
		    }
		  ip_dst[2]++;
		  ip_dst[3]=orig_ip[3];
	       }
	     ip_dst[1]++;
	     ip_dst[2]=orig_ip[2];
	  }
     }
   /* XXX.XXX.XXX.XXX */
   else if (offset[0] && offset[1] && offset[2] && offset[3])
     {
	for (j[0]=0; j[0]<=offset[1]; j[0]++)
	  {
	     for (j[1]=0; j[1]<=offset[1]; j[1]++)
	       {
		  for (j[2]=0; j[2]<=offset[2]; j[2]++)
		    {
		       for (j[3]=0; j[3]<=offset[3]; j[3]++)
			 {
			    if (send_arp(l, dev, ip_dst, enet_src, ip_src)==-1) goto error;
			    arpreply(ip_dst, dev, mode, lg);
			    ip_dst[3]++;
			 }
		       ip_dst[2]++;
		       ip_dst[3]=orig_ip[3];
		    }
		  ip_dst[1]++;
		  ip_dst[2]=orig_ip[2];
	       }
	     ip_dst[0]++;
	     ip_dst[1]=orig_ip[1];
	  }
     }
   /* paranoic test */
   else
     {
	w_error(1, "Netmask error: %s is invalid\n\n", nast_atoda(netmask));
     }

   error:
   if (mode) n_print ("winfo",2,1,lg,"\n(*) This is localhost\n\n");
   refuse:
   if (descr) pcap_close (descr);
   if (l) libnet_destroy(l);

   /* print to video (map has been called from cmd line) */
   if (mode)
     {
	n_print("winfo",1,1,lg,"                                                   \n");
	n_print("winfo",1,1,lg,"Finished\n");
	return NULL;
     }
   /* map has been called from another funz */
   else
     {
        /* number of found hosts */
	*n = k;
	return (uphost);
     }

}

/* stolen from arpreply by ? */
u_int scan_ulong(char *s, u_long *u)
{
   u_int pos;
   u_long c, result;

   pos = result = 0;

   while ((c = (u_long) (u_char) (s[pos] - '0')) < 10)
     {
	result = result * 10 + c;
	++pos;
     }
   *u = result;
   return (pos);
}

/* is it alive? */
int arpreply(u_char *t, char *dev, u_short mode,int lg)
{
   struct nast_arp_hdr *arp;
   struct libnet_ethernet_hdr *eptr;
   u_short sd, pcount;
   u_char ip[20];
   struct timeval tv;
   fd_set rfsd;

   /* retrive socket descriptor for select() funz */
   sd = pcap_fileno(descr);

   /* timeout is 5 packet or timer.. */
   pcount = 0;

   /* try for an answer ... */
   for (;;)
     {
	FD_ZERO (&rfsd);
	FD_SET (sd ,&rfsd);
	tv.tv_sec = 0;
	tv.tv_usec = 20000;

	if (pcount == 5) break;

	if (!select(sd+1, &rfsd, NULL, NULL, &tv))
	  break; /* timeout */

	if ((packet = (u_char *) pcap_next (descr, &hdr))==NULL)
	  continue;

	offset=(device(dev,descr));
	eptr = (struct libnet_ethernet_hdr *) (packet);
	arp = (struct nast_arp_hdr *)(packet+offset);

	/* It's an arp reply! */
	if ((ntohs(arp->ar_op)) == 2)
	  {
	     sprintf (ip, "%d.%d.%d.%d", arp->__ar_sip[0],arp->__ar_sip[1],arp->__ar_sip[2],arp->__ar_sip[3]);

	     if (memcmp (t, arp->__ar_sip, sizeof(arp->__ar_sip)))
	       continue;
      	     /* it's it! */
	     else
	       {
		  if (mode)
		    {
		       n_print("princ",line,1,lg,"%s \t%s (%s)\n", nast_hex_ntoa (eptr->ether_shost), ip, libnet_addr2name4(inet_addr(ip), LIBNET_RESOLVE));
		       ++line;
		    }
		  else
		    {
		       /* ask for new memory */
		       if (k) uphost = realloc (uphost, (k+1)*sizeof(struct host));
		       memcpy (uphost[k].ip,  arp->__ar_sip, 4);
		       memcpy (uphost[k].mac, eptr->ether_shost, 6);
		       k++;
		    }
	       }
	     break;
	  }
	pcount ++;
     }
   return 0;
}

/* Build our arp request */
int send_arp(libnet_t *l, u_char *device, u_char *ip_dst, u_char *enet_src, u_long ip_src)
{
   if ((ptag = libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, ARPOP_REQUEST, enet_src,
				(u_char *)&ip_src, enet_dst, ip_dst, NULL, 0, l, ptag)) == -1)
     {
	w_error(1, "libnet_build_arp error : %s\n", libnet_geterror(l));
     }

   if (!count)
     {
	count ++;
	if (libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_ARP, NULL, 0, l, 0)==-1)
	  {
	     w_error(1, "libnet_build_ethereal error : %s\n", libnet_geterror(l));
	  }
     }
   if (libnet_write(l)==-1)
     {
	w_error(1, "Error writing arp request : %s\n", libnet_geterror(l));
     }
   return 0;
}
