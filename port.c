/*
    NAST

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
    Foundation, Inc., 59 Temple Place - Suite 356, Boston, MA 02111-1567, USA.

*/

#include "include/nast.h"

/* single host syn port scanner*/
int port(char *dev,u_long dst_ip,libnet_plist_t *plist_p,int lg)
{
   int c, build_ip, fr, fd ;
   libnet_t *l;
   libnet_ptag_t tcp;
   libnet_ptag_t t;
   struct timeval tv;
   struct servent *service;
   fd_set rfsd;
   int sd,close;
   struct libnet_tcp_hdr *Tcp;
   struct libnet_ipv4_hdr *ip;
   struct libnet_icmpv4_hdr *icmp;
   u_long src_ip;
   u_char *pkt;
   u_short bport, eport, cport;
   char errbuf[LIBNET_ERRBUF_SIZE];
   int lineh;
   //char *filter="not src host 62.10.127.46";
   //char *filter="not src host 192.168.1.1";
   lineh = 1;
   pkt = NULL;
   close = bport = eport = cport = t = fr = fd = 0;


   tm = time(NULL);
   /* per avere sia ora che data si pu usare %c, ma il compilatore tira fuori dei warning decisamente noiosi:)*/
   strftime(timed,60,"%b %d %T",localtime(&tm));

   if (lg)
     {
	openfile();
	n_print (NULL,0,0,lg,"Logging to file... \n");
	fflush (stdout);
	n_print (NULL,0,0,lg,"NAST PORT SCAN REPORT\n");
	n_print (NULL,0,0,lg,"Made on %s\n\n", timed);
     }

#ifdef HAVE_LIBNCURSES
   if (graph)
     init_scr();
#endif

/* demonize */
   if (demonize)
     {
	w_error(0,"Is very useless demonize me in checking banner! Omit");
	demonize=0;
     }

   n_print("princ",lineh,2,lg,"Wait for scanning...\n\n");
   n_print("princ",++lineh,2,lg,"State	       	Port		Services		Notes\n\n");
   ++lineh;
   
   if(pcap_lookupnet(dev,&netp,&maskp,errbuf)==-1)
     {
     	w_error(1,"pcap_lookupnet() error %s\n",errbuf);
     } 

   if ((descr = pcap_open_live (dev, BUFSIZ, 0, 1, errbuf))==NULL)
     {
	w_error(1, "pcap_open_live() error: %s\n",errbuf);
     }

   sd = pcap_fileno(descr);

   if ((offset=(device(dev,descr)))==-1) return -1;

   l = libnet_init(
		   LIBNET_RAW4,                            /* injection type */
		   dev,                                   /* network interface */
		   errbuf);                                /* errbuf */

   if (l == NULL)
     {
        w_error(1, "libnet_init() failed: %s", errbuf);
     }
     
   if ((src_ip = libnet_get_ipaddr4(l))==-1)
     {
	w_error(1, "Can't get local ip address : %s\n", libnet_geterror(l));
     }
     
   /*if(pcap_compile(descr,&fp,filter,0,netp) == -1)
	  {
	     if(w_error(0, "Error in pcap_compile, insert a different filter\n")==-1)
	     	return(0);
	  }
	if(pcap_setfilter(descr,&fp) == -1)
	  {
	     w_error(1, "Error calling pcap_setfilter\n\n");
	  }*/

   tcp = 0;

   build_ip = 1;

   while (libnet_plist_chain_next_pair(plist_p, &bport, &eport))
     {
        while (!(bport > eport) && bport != 0)
	  {
	     cport = bport++;
	     tcp = libnet_build_tcp(
				    1050,                                    /* source port */
				    cport,                                    /* destination port */
				    0x01010101,                                 /* sequence number */
				    0,                                          /* acknowledgement num */
				    TH_SYN,                                     /* control flags */
				    32767,                                      /* window size */
				    0,                                          /* checksum */
				    0,                                          /* urgent pointer */
				    LIBNET_TCP_H,                               /* TCP packet size */
				    NULL,                                       /* payload */
				    0,                                          /* payload size */
				    l,                                          /* libnet handle */
				    tcp);                                         /* libnet id */
	     if (tcp == -1)
	       {
		  w_error(1, "Can't build TCP header: %s\n", libnet_geterror(l));
	       }

	     if (build_ip)
	       {
		  build_ip = 0;
		  t = libnet_build_ipv4(
					LIBNET_IPV4_H + LIBNET_TCP_H,               /* length */
					0,                                          /* TOS */
					242,                                        /* IP ID */
					0,                                          /* IP Frag */
					64,                                         /* TTL */
					IPPROTO_TCP,                                /* protocol */
					0,                                          /* checksum */
					src_ip,                                     /* source IP */
					dst_ip,                                     /* destination IP */
					NULL,                                       /* payload */
					0,                                          /* payload size */
					l,                                          /* libnet handle */
					0);
		  if (t == -1)
		    {
		       w_error(1, "Can't build IP header: %s\n", libnet_geterror(l));
		    }

	       }

	       /* usleep con be omissed when scanned another linux box,but if u scan a openBSD
	       it must be uesed! otherwise it find drop rule that doesn't exist!*/
	     //usleep(100);
	     usleep(900);
	     c = libnet_write(l);
	     if (c == -1)
	       {
		  w_error(1, "Libnet_write() Error: %s\n", libnet_geterror(l));
	       }
	       

	    for(;;)
	       {
		  fflush (logd);
	          tv.tv_sec = 2;
		  //tv.tv_usec = 75000;
		  FD_ZERO (&rfsd);
	          FD_SET (sd ,&rfsd);

		  if((pkt = (u_char *) pcap_next(descr,&hdr))==NULL)
		  	{
			break;
			}
			
		  ip = (struct libnet_ipv4_hdr *) (pkt + offset);
		  icmp = (struct libnet_icmpv4_hdr *) (pkt + offset + LIBNET_IPV4_H);
		  Tcp = (struct libnet_tcp_hdr *) (pkt + offset + LIBNET_IPV4_H);

		 
		  if (Tcp->th_flags == (TH_RST|TH_ACK))
		    {
		       close++;
		       break;
		    }
		       
		  service = getservbyport(htons(cport), "tcp");

		  if(ip->ip_p == IPPROTO_ICMP)
		    {
		       n_print("princ",lineh,2,lg,"Filtered	%d		%s",(cport), (service) ? service->s_name : "unknown");
		       if(!graph || (graph && lg)) fprintf(logd,"\t\t\t");
		       switch((icmp->icmp_type))
			 {

			  case 3:
			    switch (icmp->icmp_code)
			      {
			       case 0:
				 n_print("princ",lineh,56,lg,"Network Unreachable(*)\n");
				 break;
			       case 1:
				 n_print("princ",lineh,56,lg,"Host Unreachable(*)\n");
				 break;
			       case 2:
				 n_print("princ",lineh,56,lg,"Protocol Unreachable(*)\n");
				 break;
			       case 3:
				 n_print("princ",lineh,56,lg,"Port Unreachable(*)\n");
				 break;
			       case 9:
				 n_print("princ",lineh,56,lg,"Destination network administratively prohibited(*)\n");
				 break;
			       case 10:
				 n_print("princ",lineh,56,lg,"Destination host administratively prohibited(*)\n");
				 break;
			       case 13:
				 n_print("princ",lineh,56,lg,"Comm. administratively prohibited(*)\n");
			      }

			    break;
			  default:
			    n_print("princ",lineh,56,lg,"%d(*)\n", icmp->icmp_type);
			    break;
			 }
		       fr++;
		       ++lineh;
		       break;
		    }


		  if (!select(sd+1, &rfsd, NULL, NULL, &tv))
		    {
		       n_print("princ",lineh,2,lg,"Filtered	%d		%s", (cport),(service) ? service->s_name : "unknown");
		       if(!graph || (graph && lg)) fprintf(logd,"\t\t\t");
		       n_print("princ",lineh,56,lg,"SYN packet timeout(**)\n");
		       fd++;
		       ++lineh;
		       break;
		    }

		  if (Tcp->th_seq != 0 && (Tcp->th_flags == (TH_SYN|TH_ACK)))
		    {
		       n_print("princ",lineh,2,lg,"Open		%d		%s", cport ,(service) ? service->s_name : "unknown");
		       if(!graph || (graph && lg)) fprintf(logd,"\t\t\t");
		       n_print("princ",lineh,56,lg,"None\n");
		       ++lineh;
		       break;
		    }

	       }

	  }
     }

   n_print("winfo",1,2,lg,"\nAll the other %d ports are in state closed\n",close);
   if (fr!=0) n_print("winfo",2,1,lg,"(*)Possible REJECT rule in the firewall\n");
   if (fd!=0) n_print("winfo",3,1,lg,"(**)Possible DROP rule in the firewall\n");

   libnet_destroy(l);
   pcap_close(descr);
   n_print("princ",lineh+2,1,lg,"Scanning terminated on %s\n",timed);

   if (lg)
     {
	n_print(NULL,0,0,lg,"Done! Results has been writed to '%s'\n", logname);
	fclose (logd);
     }
   printf ("\n");
   return 0;

   if (lg)
     {
	n_print(NULL,0,0,lg,"Error! Results has been writed to '%s'\n", logname);
	fclose (logd);
     }
   printf ("\n");
   return 1;

}

/* multy hosts - catch banner*/
int mport (u_char *dev, u_short ports[],int lg)
{
   struct host *uphost;
   struct servent *service;
   struct in_addr daddr;
   u_short i, j, n;
   char banner[1024];
   char *msg = "HEAD / HTTP/1.0\n\n";
   struct sockaddr_in sin;
   char ip[20];
   int sd, r, size, bsent,z,k,x,y;
   struct timeval tv;
   fd_set rfds;
   int lineh;
   int linep;
   int len;
   char *buf_p, *banner_p, *p;
   u_char tmpbuf[1024], *ph=NULL, obuf[4];

   lineh = 3;
   linep = 6;

   if (lg)
     {
	openfile();
	n_print (NULL,0,0,lg,"Logging to file... \n");
	fflush (stdout);
	n_print (NULL,0,0,lg,"NAST BANNER SCAN REPORT\n");
	n_print (NULL,0,0,lg,"Made on %s\n\n", timed);
     }

#ifdef HAVE_LIBNCURSES
   if (graph)
     init_scr();
#endif

/* demonize */
   if (demonize)
     {
	w_error(0,"Is very useless demonize me in checking banner! Omit");
	demonize=0;
     }

   tm = time(NULL);
   strftime(timed,60,"%b %d %T",localtime(&tm));

   n_print ("princ",1,1,lg, "Builing hosts list... ");

  if ((uphost = map_lan(dev, 0, &n))==NULL)
     {
	if(w_error(0, "\nCan't build truly host list! mmhhh!\nReport bug to author please\n\n")==-1)
	  return(0);
     }
   if (n==0)
     {
        n_print("winfo",1,1,lg,"                                                        ");
	n_print("winfo",1,1,lg,"\nWhat are you doing? You are alone in this network!\n\n");
     }

   n_print("princ",1,25,lg,"done\n\n");

   memset (&sin, 0, sizeof (struct sockaddr_in));
   sin.sin_family = AF_INET;

   for (i=0; i<n; i++)
   {
   sprintf(ip, "%d.%d.%d.%d", uphost[i].ip[0], uphost[i].ip[1], uphost[i].ip[2], uphost[i].ip[3]);
   daddr.s_addr = inet_addr (ip);
   sin.sin_addr = daddr;
   j = 0;
   n_print("princ",lineh,2,lg,"IP : %s (%s)\n", ip, libnet_addr2name4(inet_addr(ip), LIBNET_RESOLVE));
   n_print("princ",++lineh,2,lg,"OPEN PORTS\t\tBANNER\n");

   for (;;)
     {
	sd = socket(AF_INET, SOCK_STREAM, 0);
	sin.sin_port = htons(ports[j]);

	if ((connect(sd, (struct sockaddr *)&sin, sizeof(sin))) != -1)
	  {
	     service = getservbyport(htons(ports[j]), "tcp");
	     n_print("princ",linep,2,lg,"%d (%s)", ports[j], service->s_name);
	     if(!graph) printf("\t\t");

	     FD_ZERO (&rfds);
	     FD_SET (sd, &rfds);
	     tv.tv_sec=2;
	     tv.tv_usec=0;
	     fcntl(sd, F_SETFL, O_NONBLOCK);
	     
	     if(ports[j]==80)
	       { 
	          select(sd+1, &rfds, NULL, NULL, &tv);
		  size = strlen(msg);
		  bzero(banner,1024);
		  bsent = send(sd, msg, size, 0);
		  r = read (sd, banner, 1024);
		  len = strlen("Server: ");

		  banner_p = (char *)malloc(strlen(banner)+1);
		  bzero(banner_p, strlen(banner)+1);

		  for(buf_p = strtok(banner, "\n"); buf_p != NULL;)
		    {
		       p = strstr(buf_p, "Server: ");
		       if(p)
			 {
			    memmove(banner_p, (p+len), strlen(buf_p)-len);
			 }
		       buf_p = strtok(NULL, "\n");
		    }
		  if(banner_p)
		    {
		       strncpy(banner, banner_p, 1024);
		    }
		  else
		    {
		       strncpy(banner, "no banner available", 1024);
		    }
		  free(banner_p);
		  if (banner[r-1]=='\n') banner[r-1]='\0';
		  n_print("princ",linep,24,lg,"%s",banner);
		  if(!graph) printf("\n");
		  ++linep;
		  close(sd);
		  j++;
		  continue;
	       }

	    if(ports[j] == 23)
	       {
	       y=0;
	       select(sd+1, &rfds, NULL, NULL, &tv);
		  do
		    {  
		       usleep(100000);
		       bzero(tmpbuf, 1024);
		       r = read (sd, tmpbuf, 1024);
		       if(r==-1)
			 break;

		       for(z = 0; z < r; z++)
			 {
			    if((z % 3) == 0 && z > 0)
			      {
				 if(tmpbuf[z-3] != 255)
				   {
				      bzero(banner, 1024);
				      z=0;
				      for(k = 0; k < r; k++)
					{
					   if(tmpbuf[k] == 255)
					     {
						k++; k++;
					     }
					   else if(tmpbuf[k] != 0 && tmpbuf[k] != 13)
					     {
						banner[z] = tmpbuf[k];
						z++;
					     }
					}
				      banner[z] = '\0';
				      break;
				   }
			      }
			 }
		       ph = tmpbuf;
		       x = strlen(tmpbuf);
		       while(x > 0)
			 {
			    obuf[0] = 255;
			    ph++; x--;
			    if( (*ph == 251) || (*ph == 252))
			      y = 254;
			    if( (*ph == 253) || (*ph == 254))
			      y = 252;
			    if(y)
			      {
				 obuf[1] = y;
				 ph++; x--;
				 obuf[2] = *ph;
				 send(sd, obuf, 3, 0);
				 y = 0;
			      }
			    ph++; x--;
			 }
		    }
		  while(ph != NULL);

		  if (banner[r-1]=='\n') banner[r-1]='\0';
		  for(i=0;i<=(strlen(banner));i++)
		  	{
			if(banner[i]=='\n'){
				banner[i]=' ';
				}
			}
		  n_print("princ",linep,24,lg,"%s\n",banner);
		  linep++;
		  close(sd);
		  j++;
		  continue;
	       }

	     

		  /* read the banner */
	     if (select (sd+1, &rfds, NULL, NULL, &tv))
	       {
		  memset (&banner, 0, 1024);
		  r = read (sd, banner, 1024);
		  if (banner[r-1]=='\n') banner[r-1]='\0';
		  n_print("princ",linep,24,lg,"%s\n", banner);
		  ++linep;
	       }
	      /* 1st time out expired */
	     else
	       {
		       /* send two \n to socket */
		  write (sd, "\n\n", 2);
		       /* reset timer */
		  FD_ZERO (&rfds);
		  FD_SET (sd, &rfds);
		  tv.tv_sec=8;
		  tv.tv_usec=0;

		       /* try a 2nd time */
		  if (select (sd+1, &rfds, NULL, NULL, &tv))
		    {
		       memset (&banner, 0, 1024);
		       r = recv (sd, banner, 1024, 0);
		       if (banner[r-1]=='\n') banner[r-1]='\0';
		       n_print("princ",linep,24,lg,"%s\n", banner);
		       ++linep;
		    }
	       }

	  }

	fflush (logd);
	close (sd);
	j++;

	if (ports[j] == '\0') break;
     }
   lineh = linep+2;
   linep = linep+5;

   if(!graph) printf("\n");

   }

   free (uphost);
   n_print("winfo",1,1,lg,"                                                        ");
   n_print("winfo",1,2,lg,"\nScanning terminated on %s\n",timed);
   if (lg)
     {
	fclose (logd);
     }

   printf ("\n");
   return 0;

}

int mhport(u_char *dev,libnet_plist_t *plist_p,int lg)
{
   int c, build_ip, fr=0, fd=0 ;
   libnet_t *l;
   libnet_ptag_t tcp=0;
   libnet_ptag_t t=0;
   struct timeval tv;
   struct servent *service;
   fd_set rfsd;
   int sd,close = 0;
   struct pcap_pkthdr pcap_h;
   struct libnet_tcp_hdr *Tcp;
   struct libnet_ipv4_hdr *ip;
   struct libnet_icmpv4_hdr *icmp;
   u_long src_ip = 0;
   u_char *pkt;
   u_short bport = 0, eport = 0, cport = 0, i = 0 ,n = 0;
   char errbuf[LIBNET_ERRBUF_SIZE];
   struct host * uphost;
   u_char testip[20];
   int lineh;
   int linep;

   lineh = 3;
   linep = 6;

   tm = time(NULL);
   strftime(timed,60,"%b %d %T",localtime(&tm));

   if (lg)
     {
	openfile();
	n_print (NULL,0,0,lg,"Logging to file... \n");
	fflush (stdout);
	n_print (NULL,0,0,lg,"NAST MULTI PORT SCAN REPORT\n");
	n_print (NULL,0,0,lg,"Made on %s\n\n", timed);
     }

#ifdef HAVE_LIBNCURSES
   if (graph)
     init_scr();
#endif

/* demonize */
   if (demonize)
     {
	w_error(0,"Is very useless demonize me in checking banner! Omit");
	demonize=0;
     }

   n_print ("princ",1,1,lg,"Builing hosts list...");

   if ((uphost = map_lan(dev, 0, &n))==NULL)
     {
	if(w_error(0, "\nCan't build truly host list! mmhhh!\nReport bug to author please\n\n")==-1)
	  return(0);
     }
   if (n==0)
     {
	if(w_error(0, "\nWhat are you doing? You are alone in this network!\n\n")==-1)
	  return(0);
     }

   n_print ("princ",1,22,lg,"done\n");

   for(i=0;i<n;i++)
     {
        usleep(6000);
       	tcp = 0; c = 0;

	l = libnet_init(
			LIBNET_RAW4,                            /* injection type */
			dev,                                   /* network interface */
			errbuf);                                /* errbuf */

	if (l == NULL)
	  {
	     w_error(1, "libnet_init() failed: %s", errbuf);
	  }
	if ((src_ip = libnet_get_ipaddr4(l))==-1)
	  {
	     w_error(1, "Can't get local ip address : %s\n", libnet_geterror(l));
	  }

	sprintf(testip, "%d.%d.%d.%d", uphost[i].ip[0], uphost[i].ip[1], uphost[i].ip[2], uphost[i].ip[3]);


	n_print("princ",++lineh,1,lg,"Wait for scanning...");
	n_print("princ",lineh,22,lg,"%d.%d.%d.%d\n\n", uphost[i].ip[0], uphost[i].ip[1], uphost[i].ip[2], uphost[i].ip[3]);
	n_print("princ",++lineh,2,lg,"State		Port		Services		Notes\n\n");
	
	pcap_lookupnet(dev,&netp,&maskp,errbuf);
        
	++lineh;
	
	if ((descr = pcap_open_live (dev, BUFSIZ, NOT_PROMISC, 10,errbuf)) == NULL)
	  {
	     w_error(1,"pcap_open_live() error: %s\n",errbuf);
	  }

	sd = pcap_fileno(descr);

	if ((offset=(device(dev,descr)))==-1) return -1;

	build_ip = 1;
	while (libnet_plist_chain_next_pair(plist_p, &bport, &eport))
	  {
	     while (!(bport > eport) && bport != 0)
	       {
		  cport = bport++;
		  tcp = libnet_build_tcp(
					 1050,                                    /* source port */
					 cport,                                    /* destination port */
					 1234567,                                 /* sequence number */
					 0,                                          /* acknowledgement num */
					 TH_SYN,                                     /* control flags */
					 32767,                                      /* window size */
					 0,                                          /* checksum */
					 0,                                          /* urgent pointer */
					 LIBNET_TCP_H,                               /* TCP packet size */
					 NULL,                                       /* payload */
					 0,                                          /* payload size */
					 l,                                          /* libnet handle */
					 tcp);                                         /* libnet id */
		  if (tcp == -1)
		    {
		       libnet_destroy(l);
		       pcap_close(descr);
		       w_error(1, "Can't build TCP header: %s\n", libnet_geterror(l));

		    }

		  if (build_ip)
		    {
		       build_ip = 0;
		       t = libnet_build_ipv4(
					     LIBNET_IPV4_H + LIBNET_TCP_H,               /* length */
					     0,                                          /* TOS */
					     242,                                        /* IP ID */
					     0,                                          /* IP Frag */
					     64,                                         /* TTL */
					     IPPROTO_TCP,                                /* protocol */
					     0,                                          /* checksum */
					     src_ip,                                     /* source IP */
					     inet_addr(testip),                                     /* destination IP */
					     NULL,                                       /* payload */
					     0,                                          /* payload size */
					     l,                                          /* libnet handle */
					     0);
		       if (t == -1)
			 {  
			    libnet_destroy(l);
		            pcap_close(descr);
			    w_error(1, "Can't build IP header: %s\n", libnet_geterror(l));
			 }

		    }
		  //usleep(5);
		  c = libnet_write(l);
		  if (c == -1)
		    {
		       w_error(1, "Error: %s\n", libnet_geterror(l));
		    }

		  for(;;)
		    {
		       fflush (logd);

		       tv.tv_sec = 2;
		       FD_ZERO (&rfsd);
		       FD_SET (sd ,&rfsd);

		       pkt = (u_char *) pcap_next(descr,&pcap_h);
		       ip = (struct libnet_ipv4_hdr *) (pkt + offset);
		       icmp = (struct libnet_icmpv4_hdr *) (pkt + offset + LIBNET_IPV4_H);
		       Tcp = (struct libnet_tcp_hdr *) (pkt + offset + sizeof(struct libnet_ipv4_hdr));

		       if (Tcp->th_flags == (TH_RST|TH_ACK))
			 {
			    close++;
			    break;
			 }

		       service = getservbyport(htons(cport), "tcp");

     		/*ho lasciato gli icmp pi logici x un filtraggio...dubito che vada bene un echo_request:)*/
		       if(ip->ip_p == IPPROTO_ICMP)
			 {
			    n_print("princ",lineh,2,lg,"Filtered	%d		%s", cport, (service) ? service->s_name : "unknown");
			    if(!graph || (graph && lg)) fprintf(logd,"\t\t\t");
			    switch((icmp->icmp_type))
			      {

			       case 3:
				 switch (icmp->icmp_code)
				   {
				    case 0:
				      n_print("princ",lineh,56,lg,"Network Unreachable(*)\n");
				      break;
				    case 1:
				      n_print("princ",lineh,56,lg,"Host Unreachable(*)\n");
				      break;
				    case 2:
				      fprintf(logd,"Protocol Unreachable(*)\n");
				      break;
				    case 3:
				      n_print("princ",lineh,56,lg,"Port Unreachable(*)\n");
				      break;
				    case 9:
				      n_print("princ",lineh,56,lg,"Destination network administratively prohibited(*)\n");
				      break;
				    case 10:
				      n_print("princ",lineh,56,lg,"Destination host administratively prohibited(*)\n");
				      break;
				    case 13:
				      n_print("princ",lineh,56,lg,"Comm. administratively prohibited(*)\n");
				      break;
				   }

				 break;
			       default:
				 n_print("princ",lineh,56,lg,"%i(*)\n", icmp->icmp_type);
				 break;
			      }
			    fr++;
			    ++lineh;
			    break;
			 }

		       if (!select(sd+1, &rfsd, NULL, NULL, &tv))
			 {
			    n_print("princ",lineh,2,lg,"Filtered	%d		%s", cport,(service) ? service->s_name : "unknown");
			    if(!graph || (graph && lg)) fprintf(logd,"\t\t\t");
			    n_print("princ",lineh,56,lg,"SYN packet timeout(**)\n");
			    fd++;
			    ++lineh;
			    break;
			 }
			 
		       if (Tcp->th_seq != 0 && (Tcp->th_flags == (TH_SYN|TH_ACK)))
			 {
			    n_print("princ",lineh,2,lg,"Open		%d		%s", cport,(service) ? service->s_name : "unknown");
			    if(!graph || (graph && lg)) fprintf(logd,"\t\t\t");
			    n_print("princ",lineh,56,lg,"None\n");
			    ++lineh;
			    break;
			 }

		    }

	       }
	  }
	n_print("princ",++lineh,2,lg,"\nAll the other %d ports are in state closed\n",close);
	if (fr!=0) n_print("princ",++lineh,1,lg,"(*)Possible REJECT rule in the firewall\n");
	if (fd!=0) n_print("princ",++lineh,1,lg,"(**)Possible DROP rule in the firewall\n");

	libnet_destroy(l);
	pcap_close(descr);
	close=0;
	fd = 0; fr =0;
	lineh = lineh+2;
     }

   free (uphost);
   n_print("winfo",2,2,lg,"Scanning terminated on %s\n",timed);
   if (lg)
     {
	printf ("Done! Results has been writed to '%s'\n", logname);
	fclose (logd);
     }

   printf ("\n");
   return 0;

}

