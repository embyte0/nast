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

/* prototypes */
void sniff (int d, int x, FILE *output, FILE *ldd);
int run_sniffer (u_short promisc, u_short data, u_short hex, u_short f, u_short l, u_short tcpdlog, u_short tcpdread, char *filter, char *dev, char *ldname);

/* plugin to run sniffer */
int run_sniffer (u_short promisc, u_short data, u_short hex, u_short f, u_short l, u_short tcpdlog, u_short tcpdread, char *filter, char *dev, char *ldname)
{
   char *mask;
   char errbuf[PCAP_ERRBUF_SIZE];
   libnet_t *L;
   int ld;
   struct libnet_ether_addr *e;
   struct in_addr addr;
   /* log data FILE descriptor */
   FILE *ldd;

   ldd = NULL;
   ld = 0;
   npkt = 0;
   if (strcmp (ldname, "NULL")) /* != NULL */
     (ld=1);

   /* ask pcap for the network address and mask of the device */
   if ((pcap_lookupnet(dev,&netp,&maskp,errbuf))==-1)
     {
	w_error(1, "pcap_lookupnet error: %s\n\n", errbuf);
     }

   if (tcpdlog) /* write in tcdl file in tcpdump log format */
     {
	if ((descr = pcap_open_live (dev, BUFSIZ, promisc, 10, errbuf))==NULL)
	  {
	     w_error(1, "pcap_open_live() error: %s\n\n",errbuf);
	  }

	if ((dumper = pcap_dump_open(descr,tcpdl))==NULL)
	  {
	     w_error(1, "pcap_dump_open() error: %s\n\n",errbuf);
	  }
     }

   else if(tcpdread) /* read from tcpdl file */
     {
	if ((descr = pcap_open_offline(tcpdl,errbuf))==NULL)
	  {
	     w_error(1, "pcap_open_offline() error: %s\n\n",errbuf);
	  }
     }
   /* normal case */
   else if ((descr = pcap_open_live (dev, BUFSIZ, promisc, 10, errbuf))==NULL)
     {
	w_error(1, "pcap_open_live() error: %s\n\n",errbuf);
     }

   if ((offset=(device(dev,descr)))==-1) return -1;
   
   L = libnet_init (LIBNET_LINK, dev, errbuf);

   e = libnet_get_hwaddr(L);
   if (!e)
     {
	w_error(1, "Can't get hardware address: %s\n\n", libnet_geterror(L));
     }

   addr.s_addr = maskp;
   if ((mask = inet_ntoa(addr))==NULL)
     {
	w_error(1, "Impossible get the mask\n\n");
     }

   if(!graph)
     {
	printf("%sSniffing on:\n\n%s", CYAN, NORMAL);
	printf("%s- Device:\t%s%s\n",BOLD, NORMAL, dev);
	printf("%s- MAC address:\t%s%s\n", BOLD, NORMAL, nast_hex_ntoa (e->ether_addr_octet));
	printf("%s- IP address:\t%s%s\n", BOLD, NORMAL, libnet_addr2name4(libnet_get_ipaddr4(L), 0));
	printf("%s- Netmask:\t%s%s\n",BOLD, NORMAL, mask);

	printf("%s- Promisc mode:\t%s", BOLD, NORMAL);
	if (promisc) printf("Set\n");
	else printf("Not set\n");

	printf ("%s- Filter:\t%s", BOLD, NORMAL);
	if (filter) printf("%s\n", filter);
	else printf("None\n");

	printf("%s- Logging:\t%s", BOLD, NORMAL);
	if (!ld && !l) printf ("None\n");
	else if (ld && !l) printf ("Sniffed data\n");
	else if (!ld && l) printf ("Traffic\n");
	else if (ld && l) printf ("Traffic and Sniffed data\n");
     }
   /* log all packets */
   if (l)
     {
	openfile();

	fprintf(logd, "NAST SNIFFER LOGGING REPORT\n");
	fprintf(logd, "Made on %s, device %s (%s)\n\n", timed, dev, libnet_addr2name4(libnet_get_ipaddr4(L), 0));
     }

   /* log only data */
   if (ld)
     {
	if ((ldd = (fopen(ldname,"w"))) == NULL)
	  {
	     w_error(1, "\nError: unable to open logfile descriptor: %s\n\n", strerror(errno));
	  }

	fprintf(ldd, "NAST SNIFFED DATA REPORT\n");
	fprintf(ldd, "Made on %s, device %s (%s)\n\n", timed, dev, libnet_addr2name4(libnet_get_ipaddr4(L), 0));
     }

   libnet_destroy(L);

   if (f)
     {
	if(pcap_compile(descr,&fp,filter,0,netp) == -1)
	  {
	     if(w_error(0, "Error in pcap_compile, insert a different filter\n")==-1)
	     	return(0);
	  }
	if(pcap_setfilter(descr,&fp) == -1)
	  {
	     w_error(1, "Error calling pcap_setfilter\n\n");
	  }

     }

   /* demonize only now */
   if (demonize)
     bkg();

   /* sniff here */
   while(1)
     {
	  (packet = (u_char *) pcap_next (descr, &hdr));
	  if(packet==NULL) 
		continue;

	     ++npkt;
	     
	     if (!ldname)
	        sniff (data, hex, stdout, NULL);
		
	     /* print to stdout and write to data file*/
	     /* this works also for tcpdump read file!! */
	     else
	       {
		  sniff (data, hex, stdout, ldd);        
		  fflush (ldd);
	       }

	     if (l)
	       {
		  sniff (data, hex, logd, NULL);          /* log packets to file */
		  fflush (logd);
	       }

	     if (tcpdlog)
	       {
	          fflush((FILE *)dumper);
	          pcap_dump((u_char *)dumper,&hdr,packet);  
	       }

     }

   if (l) 
     fclose (logd);
   if (ldname) 
     fclose (ldd);
   return 0;
}

/* sniffer function heandler */
void sniff (int d, int x, FILE *output, FILE *ldd)
{
   struct libnet_ipv4_hdr *ip;
   u_int16_t type;

   type = handle_ethernet (packet);

   if ((type==ETHERTYPE_ARP) || (type==ETHERTYPE_REVARP))
     handle_ARP(output);

   ip = (struct libnet_ipv4_hdr *) (packet+offset);
   switch(ip->ip_p)
     {
      case IPPROTO_TCP:
	handle_TCP (d, x, output, ldd);
	break;
      case IPPROTO_UDP:
	handle_UDP (d, x, output, ldd);
	break;
      case IPPROTO_ICMP:
	handle_ICMP (d, x, output, ldd);
	break;
      case IPPROTO_IGMP:
	handle_IGMP (output);
	break;
     }

}
