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

void init_curs(void);
void title(void);
int get_info(void);

int main_graph(void)
{

   int row,col;
   char errbuf[PCAP_ERRBUF_SIZE];
   char currfil[200];
   char devapp[10];
   int key, c, out;
   int ris;
   int l,i,n,ok,x;
   u_long seq;
   u_long ack;
   u_long s_ip;
   u_long d_ip;
   u_short s_port,d_port;
   int res;
   pcap_if_t *devices;
   pcap_if_t *devc;

   key = c = 0xff;/*unuse value*/
   strcpy(n_filter,"NULL");
   strcpy(ldfile,"NULL");
   strcpy(devapp,"NULL");
   ris = out = f = hex = ascii = ld = tl = tr = lr = mvar = linm = n = ok = x = 0;
   promisc = 1;
   seq = ack = s_ip = d_ip = s_port = d_port = 0;
   l = 3;
   stream_glob = bc_glob = sniff_glob = rst_glob = 0;
   flg = 0;

   init_curs();

   getmaxyx(stdscr,row,col);
   if(row<24 || col<78)
     {
	endwin();
	printf("\nSorry,you must have a screen of at least 85 colons and 31 rows\n\n");
	exit(1);
     }

   if (princ == NULL)
     {

	princ = newscrollwin(LINES-13, COLS, 6, 0, " Main Window (F2)", 10000);
	SAFE_SCROLL_REFRESH(princ);
     }
   if (winfo == NULL)
     {

	winfo = newscrollwin(7, COLS, LINES-7, 0,  " Info Window (F3)", 300);
	SAFE_SCROLL_REFRESH(winfo);
     }

   winscroll(princ, -10000);  // rewind the scrollbar
   winscroll(winfo,-300);  // rewind the scrollbar

   redrawscrollwin(princ, 0);
   redrawscrollwin(winfo, 0);

   refresh();

   title();

   nmenu();

   redrawscrollwin(princ, 0);
   redrawscrollwin(winfo, 0);
   
   /*finding a suitable device */
   res = pcap_findalldevs(&devices, errbuf);
   if (res < 1 && 0) {
    fprintf(stderr, "pcap_findalldevs error: %s\n", errbuf);
    return -1;
   }
        
   /* try to find the device */
    for (devc = devices; devc; devc = devc->next) {
	if (!strcmp(devc->name,"any"))
		continue;
	if (devc->flags & PCAP_IF_LOOPBACK) {
		strcpy(dev,devc->name); 
		continue; }
	else {
		 strcpy(dev,devc->name);
		 break;
		}
      }

   pcap_freealldevs(devices);

   while(!ok)
     {
	pop_up_win();
	mvwprintw(pop_up,2,2,"Welcome to Nast, the Network Analyzer Sniffer Tool!");
	mvwprintw(pop_up,4,6,"    Distribuited under GPL license by");
	mvwprintw(pop_up,5,6,"      Embyte & Snifth (C) 2003-2004");
	mvwprintw(pop_up,8,6,"Insert the device you want to use, please:");
	mvwprintw(pop_up,9,6,"   for the default <%s> press enter!",dev);
	wmove(pop_up,9,23);
	echo();
	mvwgetnstr(pop_up,11,25,devapp,10);
	if(!strcmp(devapp,"")) ;
	  else strcpy(dev,devapp);
	noecho();
	if ((pcap_lookupnet(dev,&netp,&maskp,errbuf))==-1)
	  {
	     w_error(0, "          Impossible to use device: %s",dev);
	  }
	else ok = 1;
     }

   delwin(pop_up);
   redrawscrollwin(princ,0);
   nmenu();

   do
     {

	redrawscrollwin(princ, 0);
	redrawscrollwin(winfo, 0);
        title();
	key=getch();

	switch(key)
	  {
	   case KEY_F(1):
	     flg=1;
	     nmenu();
	     while( (out!=1) && ((c = wgetch(my_nmenu_win)) != 'q') )
	       {
		  switch(c)
		    {
		     case KEY_LEFT:
		       menu_driver(my_nmenu, REQ_PREV_ITEM);
		       break;
		     case KEY_RIGHT:
		       menu_driver(my_nmenu, REQ_NEXT_ITEM);
		       break;
		     case 10:
		       curr_item = current_item(my_nmenu);
		       switch(item_index(curr_item))
			 {
			  case 0:
			    sniffer:
			    box(my_nmenu_win, 0, 0);
			    wrefresh(my_nmenu_win);
			    redrawscrollwin(princ, 0);
			    ris = sniffer_menu();
			    if (ris == -1)
			      {
				 menu_driver(my_nmenu, REQ_RIGHT_ITEM);
				 goto analyzer;
			      }
			    if (ris == -2)
			      {
				 menu_driver(my_nmenu, REQ_LAST_ITEM);
				 goto options;
			      }
			    if(ris == 0)
			      {
				 (out=1);
				 menu_driver(my_nmenu, REQ_FIRST_ITEM);
			      }

			    break;
			  case 1:
			    analyzer:
			    box(my_nmenu_win, 0, 0);
			    wrefresh(my_nmenu_win);
			    redrawscrollwin(princ, 0);
			    ris = analyzer_menu();
			    if (ris == -1)
			      {
				 menu_driver(my_nmenu, REQ_RIGHT_ITEM);
				 goto options;
			      }
			    if (ris == -2)
			      {
				 menu_driver(my_nmenu, REQ_LEFT_ITEM);
				 goto sniffer;
			      }

			    if(ris == 0)
			      {
				 (out=1);
				 menu_driver(my_nmenu, REQ_FIRST_ITEM);
			      }

			    break;
			  case 2:
			    options:
			    box(my_nmenu_win, 0, 0);
			    wrefresh(my_nmenu_win);
			    redrawscrollwin(princ, 0);
			    ris = options_menu();
			    if (ris == -1)
			      {
				 menu_driver(my_nmenu, REQ_LEFT_ITEM);
				 goto analyzer;
			      }
			    if (ris == -2)
			      {
				 menu_driver(my_nmenu, REQ_FIRST_ITEM);
				 goto sniffer;
			      }

			    if(ris == 0)
			      {
				 (out=1);
				 menu_driver(my_nmenu, REQ_FIRST_ITEM);
			      }

			    break;
			 }
		       box(my_nmenu_win, 0, 0);
		       wrefresh(my_nmenu_win);
		       pos_menu_cursor(my_nmenu);
		       redrawscrollwin(princ, 0);
		       flg=0;
		       nmenu();
		       break;
		    }

	       }
	     flg=0;
	     redrawscrollwin(princ,0);
	     nmenu();
	     out=0;
	     break;

	   case KEY_F(2):
	     while((c = getch()) != 'q')
	       {
		  switch(c)
		    {
		     case KEY_UP:
		       winscroll(princ, -1);  // rewind the scrollbar
		       break;
		     case KEY_DOWN:
		       winscroll(princ, +1);  // rewind the scrollbar
		       break;
		     case KEY_NPAGE:
		       winscroll(princ, +10);  // rewind the scrollbar
		       break;
		     case KEY_PPAGE:
		       winscroll(princ, -10);  // rewind the scrollbar
		       break;
		    }
		  redrawscrollwin(princ, 0);
	       }
	     break;

	   case KEY_F(3):
	     while((c = getch()) != 'q')
	       {
		  switch(c)
		    {
		     case KEY_UP:
		       winscroll(winfo, -1);  // rewind the scrollbar
		       break;
		     case KEY_DOWN:
		       winscroll(winfo, +1);  // rewind the scrollbar
		       break;
		     case KEY_NPAGE:
		       winscroll(winfo, +5);  // rewind the scrollbar
		       break;
		     case KEY_PPAGE:
		       winscroll(winfo, -5);  // rewind the scrollbar
		       break;
		    }
		  redrawscrollwin(winfo, 0);
	       }
	     break;

	   case 'S':
	     flg=1;
	     nmenu();
	     menu_driver(my_nmenu, REQ_FIRST_ITEM);
	     goto sniffer;
	     break;
	   case 'A':
	     flg=1;
	     nmenu();
	     menu_driver(my_nmenu, REQ_NEXT_ITEM);
	     goto analyzer;
	     break;
	   case 'O':
	     flg=1;
	     nmenu();
	     menu_driver(my_nmenu, REQ_LAST_ITEM);
	     goto options;
	     break;
	   case 'i':
	     get_info();
	     break;
	   case 'd':
	     werase(winfo->win);
	     redrawscrollwin(winfo,0);
	     break;
	   case 'x':
	     werase(princ->win);
	     redrawscrollwin(princ,0);
	     break;
	   case 'h':
	     help_win();
	     mvwprintw(help,2,2,"[F1]          -> Menu Selection");
	     mvwprintw(help,3,2,"[F2]          -> Main window interactions");
	     mvwprintw(help,4,2,"[F3]          -> Info window interactions");
	     mvwprintw(help,5,2,"[UP]          -> Scrolling UP windows (1 line)");
	     mvwprintw(help,6,2,"[DOWN]        -> Scrolling DOWN windows (1 line)");
	     mvwprintw(help,7,2,"[PgUP]        -> Scrolling UP windows (5 lines)");
	     mvwprintw(help,8,2,"[PgDOWN]      -> Scrolling DOWN windows (5 lines)");
	     mvwprintw(help,9,2,"[Shift + s]   -> Sniffer Menu");
	     mvwprintw(help,10,2,"[Shift + a]   -> Analyzer Menu");
	     mvwprintw(help,11,2,"[Shift + o]   -> Options Menu");
	     mvwprintw(help,12,2,"[i]           -> Show informations about options");
	     mvwprintw(help,13,2,"[x]           -> Erase Main Window");
	     mvwprintw(help,14,2,"[d]           -> Erase Info window");
	     mvwprintw(help,15,2,"[h]           -> This help");
	     mvwprintw(help,16,2,"[q]           -> Exit all windows");
	     mvwprintw(help,17,2,"When you use the sniffer pay attention that the");
	     mvwprintw(help,18,2,"options will be selected BEFORE sniffer starting!");
	     mvwprintw(help,20,2,"[Shift + q]   -> Exit NAST");
	     do
	       {
		  ris=wgetch(help);

	       }
	     while( ris != 'q');
	     wrefresh(help);
	     werase(help);
	     nmenu();
	     redrawscrollwin(princ,0);
	     redrawscrollwin(winfo,0);
	     break;

	   case 'Q':
	     pop_up_win();
	     mvwprintw(pop_up,7,10,"Are you sure you want to exit (y/n)?");
	     wmove(pop_up,4,2);
	     do
	       {
		  ris=wgetch(pop_up);
		  if (ris == 'y')
		    {
		       shutdown_thread();
		       endwin();
		       printf("Thank you for using Nast\n\n");
		       exit(0);
		    }

		  else if (ris == 'n');
	       }
	     while( ris != 'y' && ris != 'n');
	     delwin(pop_up);
	     redrawscrollwin(princ,0);
	     break;

	   case 's':
	     if(!stream_glob)
	       break;

	     i = 0;
	     l = 1;
	     while((c = getch()) != 'q')
	       {
		  switch(c)
		    {
		     case KEY_DOWN:
		       memset(&currfil, 0, sizeof(currfil));

		       if(l>=(nmax-1))
			 break;

		       else
			 {

			    wmove(winfo->win, l, 2);
			    wattron(winfo->win, COLOR_PAIR(4));
			    waddstr(winfo->win, sf[i].string);
			    wattroff(winfo->win, COLOR_PAIR(4));
			    strcpy(currfil,sf[i].sfilter);
			 }
		       if(l>4)
			 {
			    winscroll(winfo,+1);
			    SAFE_SCROLL_REFRESH(winfo);
			 }

		       if(l==1)
			 ;
		       else
			 {
			    wmove(winfo->win, --l, 2);
			    wattron(winfo->win, A_NORMAL);
			    waddstr(winfo->win, sf[--i].string);
			    wattroff(winfo->win, A_NORMAL);
			    ++l;
			    ++i;
			 }
		       redrawscrollwin(winfo, 0);
		       strcpy(currfil,sf[i].sfilter);
		       ++l;
		       ++i;

		       break;

		     case KEY_UP:
		       memset(&currfil, 0, sizeof(currfil));

		       if (l<=2) break;

		       winscroll(winfo,-1);
		       SAFE_SCROLL_REFRESH(winfo);

		       --l;
		       --i;

		       if(l==1)
		         ;
		       else
			 {
			    wmove(winfo->win, --l, 2);
			    wattron(winfo->win, COLOR_PAIR(4));
			    waddstr(winfo->win, sf[--i].string);
			    wattroff(winfo->win, COLOR_PAIR(4));
			    strcpy(currfil,sf[i].sfilter);
			    ++l;
			    ++i;

			    wmove(winfo->win, l, 2);
			    wattron(winfo->win, A_NORMAL);
			    waddstr(winfo->win, sf[i].string);
			    wattroff(winfo->win, A_NORMAL);

			    redrawscrollwin(winfo, 0);

			 }
		       break;

		     case 10:
		       if(currfil==0)
			 break;
		       if (x)
			 {
			    pthread_cancel(thID[5]);
			    pthread_join(thID[5],NULL);
			 }
		       x=1;
		       streamg (dev,currfil);
		       break;
		    }

	       }
	     break;

	   case 'r':
	     if(!rst_glob)
	       break;

	     i = 0;
	     l = 1;
	     while((c = getch()) != 'q')
	       {
		  switch(c)
		    {
		     case KEY_DOWN:
		       memset(&currfil, 0, sizeof(currfil));
		       ack=0;
		       seq=0;

		       if(l>=(nmax-1))
			 break;

		       else
			 {

			    wmove(winfo->win, l, 2);
			    wattron(winfo->win, COLOR_PAIR(4));
			    waddstr(winfo->win, sf[i].string);
			    wattroff(winfo->win, COLOR_PAIR(4));
			    strcpy(currfil,sf[i].sfilter);
			    seq=sf[i].seq;
			    ack=sf[i].ack;
			    s_ip=sf[i].ip_src;
			    d_ip=sf[i].ip_dst;
			    s_port=sf[i].s_port;
			    d_port=sf[i].d_port;
			 }
		       if(l>4)
			 {
			    winscroll(winfo,+1);
			    SAFE_SCROLL_REFRESH(winfo);
			 }

		       if(l==1)
			 ;
		       else
			 {
			    wmove(winfo->win, --l, 2);
			    wattron(winfo->win, A_NORMAL);
			    waddstr(winfo->win, sf[--i].string);
			    wattroff(winfo->win, A_NORMAL);
			    ++l;
			    ++i;
			 }
		       redrawscrollwin(winfo, 0);
		       strcpy(currfil,sf[i].sfilter);
		       seq=sf[i].seq;
		       ack=sf[i].ack;
		       s_ip=sf[i].ip_src;
		       d_ip=sf[i].ip_dst;
		       s_port=sf[i].s_port;
		       d_port=sf[i].d_port;
		       ++l;
		       ++i;

		       break;

		     case KEY_UP:
		       memset(&currfil, 0, sizeof(currfil));
		       seq=0;
		       ack=0;

		       if (l<=2) break;

		       winscroll(winfo,-1);
		       SAFE_SCROLL_REFRESH(winfo);

		       --l;
		       --i;

		       if(l==1)
		         ;
		       else
			 {
			    wmove(winfo->win, --l, 2);
			    wattron(winfo->win, COLOR_PAIR(4));
			    waddstr(winfo->win, sf[--i].string);
			    wattroff(winfo->win, COLOR_PAIR(4));
			    strcpy(currfil,sf[i].sfilter);
			    seq=sf[i].seq;
			    ack=sf[i].ack;
			    s_ip=sf[i].ip_src;
			    d_ip=sf[i].ip_dst;
			    s_port=sf[i].s_port;
			    d_port=sf[i].d_port;
			    ++l;
			    ++i;

			    wmove(winfo->win, l, 2);
			    wattron(winfo->win, A_NORMAL);
			    waddstr(winfo->win, sf[i].string);
			    wattroff(winfo->win, A_NORMAL);

			    redrawscrollwin(winfo, 0);

			 }
		       break;

		     case 10:
		       if(currfil==0)
			 break;

		       for(n=0;n<3;n++)
		         reset_conn(dev,s_ip,d_ip,s_port,d_port,seq,ack);
		       break;
		    }

	       }
	     break;

	  }

     }
   while (key!='X');

   init_scr();
   shutdown_thread();
   endwin();
   printf("Thanx you for using NAST\n\n");

   exit(0);
}

void init_curs(void)
{

		/* Initialize curses */
   initscr();

   start_color();
   cbreak();
   noecho();
   keypad(stdscr, TRUE);

   curs_set(0);
   init_pair(1, COLOR_BLACK, COLOR_GREEN);
   init_pair(2, COLOR_CYAN, COLOR_BLACK);
   init_pair(3, COLOR_GREEN, COLOR_BLACK);
   init_pair(4, COLOR_WHITE, COLOR_BLUE);
   init_pair(5, COLOR_WHITE, COLOR_BLACK);

}

void title(void)
{
   char TITLE[]=
     {
	"NAST - NETWORK ANALYZER SNIFFER TOOL -"
     };

   WINDOW *title;
   title = subwin(stdscr,3,COLS,0,0);
   wbkgd(title,COLOR_PAIR(1));
   box(title,0,0);
   mvwprintw(title,1,(COLS-sizeof(TITLE))/2, TITLE);
   wrefresh(title);
}

int get_info()
{
   char *mask;
   char errbuf[PCAP_ERRBUF_SIZE];
   libnet_t *L;
   struct libnet_ether_addr *e;
   struct in_addr addr;

   werase(winfo->win);

	/* ask pcap for the network address and mask of the device */
   if ((pcap_lookupnet(dev,&netp,&maskp,errbuf))==-1)
     {
	if(w_error(0, "pcap_lookupnet error: %s", errbuf)==-1)
	  return(0);
     }

   if ((descr = pcap_open_live (dev, BUFSIZ, promisc, 10, errbuf))==NULL)
     {
	w_error(1, "pcap_open_live() error: %s",errbuf);
     }

   if ((offset=(device(dev,descr)))==-1)
     return -1;

   L = libnet_init (LIBNET_LINK, dev, errbuf);

   e = libnet_get_hwaddr(L);
   if (!e)
     {
	w_error(1, "Can't get hardware address: %s", libnet_geterror(L));
     }

   addr.s_addr = maskp;
   if ((mask = inet_ntoa(addr))==NULL)
     {
	w_error(1, "Impossible get the mask");
     }

   mvwprintw(winfo->win,1,2,"IP: ");
   wattron(winfo->win,A_BOLD);
   mvwprintw(winfo->win,1,13,"%s", libnet_addr2name4(libnet_get_ipaddr4(L), 0));
   wattroff(winfo->win,A_BOLD);
   mvwprintw(winfo->win,1,30,"MAC: ");
   wattron(winfo->win,A_BOLD);
   mvwprintw(winfo->win,1,39,"%s", nast_hex_ntoa (e->ether_addr_octet));
   wattroff(winfo->win,A_BOLD);
   mvwprintw(winfo->win,2,2,"Netmask: ");
   wattron(winfo->win,A_BOLD);
   mvwprintw(winfo->win,2,13,"%s",mask);
   wattroff(winfo->win,A_BOLD);
   mvwprintw(winfo->win,2,30,"Promisc: ");
   wattron(winfo->win,A_BOLD);
   if (promisc) mvwprintw(winfo->win,2,39,"Enable");
   else mvwprintw(winfo->win,2,39,"Disable");
   wattroff(winfo->win,A_BOLD);
   mvwprintw(winfo->win,1,60,"Iface: ");
   wattron(winfo->win,A_BOLD);
   mvwprintw(winfo->win,1,67,"%s",dev);
   wattroff(winfo->win,A_BOLD);
   mvwprintw(winfo->win,2,60,"ASCII: ");
   wattron(winfo->win,A_BOLD);
   if (ascii) mvwprintw(winfo->win,2,67,"Enable");
   else mvwprintw(winfo->win,2,67,"Disable");
   wattroff(winfo->win,A_BOLD);
   mvwprintw(winfo->win,3,2,"ASCII-HEX: ");
   wattron(winfo->win,A_BOLD);
   if (hex) mvwprintw(winfo->win,3,13,"Enable");
   else mvwprintw(winfo->win,3,13,"Disable");
   wattroff(winfo->win,A_BOLD);
   mvwprintw(winfo->win,3,30,"Filter: ");
   wattron(winfo->win,A_BOLD);
   mvwprintw(winfo->win,3,39,"%s",n_filter);
   wattroff(winfo->win,A_BOLD);
   mvwprintw(winfo->win,3,60,"Log Data: ");
   if(ld)
     {  wattron(winfo->win,A_BOLD);
	mvwprintw(winfo->win,3,70,"Enable");
	wattroff(winfo->win,A_BOLD);
	mvwprintw(winfo->win,3,76,", Datafile: %s", ldfile);
     }
   else
     {
	wattron(winfo->win,A_BOLD);
	mvwprintw(winfo->win,3,70,"Disable");
	wattroff(winfo->win,A_BOLD);
     }

   wrefresh(winfo->win);

   libnet_destroy(L);

   return(0);

}

void pop_up_win(void)
{
   char message[23];
   sprintf(message," Input Window ");
   pop_up = newwin(17,55,(LINES-17)/2,(COLS-55)/2);
   wbkgd(pop_up,COLOR_PAIR(4));
   box(pop_up,0,0);
   mvwprintw(pop_up,0,(55 -strlen(message))/2, message);
   wrefresh(pop_up);
}

void help_win(void)
{
   char message[23];
   sprintf(message," Help ");
   help = newwin(23,67,(LINES-23)/2,(COLS-67)/2);
   wbkgd(help,COLOR_PAIR(4));
   box(help,0,0);
   mvwprintw(help,0,(67 -strlen(message))/2, message);
   wrefresh(help);
}

#endif

