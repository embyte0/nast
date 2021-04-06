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

int tmp;

int ng_print(char *wins, int y, int x, char *string)
{

   N_SCROLLWIN *w;
   int ris;

   ris = 0;
   w = NULL;

   if(wins==NULL)
     return(0);

   if(!strcmp(wins,"princ"))
     w=princ;
   if(!strcmp(wins,"winfo"))
     w=winfo;
   if(!strcmp(wins,"pop"))
     {
	pop_up_win();
	if(string[strlen(string)-1]=='\n')
		(string[strlen(string)-1]='\0');
	mvwprintw(pop_up,y,x,"%s",string);
	mvwprintw(pop_up,11,13,"Press 'q' to close this window");
	wrefresh(pop_up);
	do
	  {
	     ris=wgetch(pop_up);
	  }
	while(ris!='q');
	delwin(pop_up);
	nmenu();
	redrawscrollwin(winfo,0);
        redrawscrollwin(princ,0);
	return 0;
     }
     
   if(string[0]=='\n')
	string[0]=' ';
     
   if(string[strlen(string)-1]=='\n')
	(string[strlen(string)-1]='\0');

   mvwprintw(w->win,y,x,"%s",string);
   
   if(sniff_glob)
   	{
	if(!mvar)
     	   SAFE_SCROLL_REFRESH(w);
	else ;
	}

   if(!sniff_glob)
       	  SAFE_SCROLL_REFRESH(w); 	

   if(w==princ)
     {
	if(y!=tmp)
	  {
	     if(line_s>LINES-16)
	       {
		  if(!mvar)
		    {
		       winscroll(princ,linm);
		       winscroll(princ,+(y-tmp));
		       linm=0;
		    }
		  else linm+=y-tmp;
	       }
	  }
	tmp=y;
     }

   if(line_s >= 10000)
     {
	werase(princ->win);
	winscroll(princ,-10000);
	line_s=0;
	row_s=0;
     }

  return 0;
}

void init_scr(void)
{
   werase(princ->win);
   werase(winfo->win);

   winscroll(princ, -10000);  // rewind the scrollbar
   winscroll(winfo,-300);  // rewind the scrollbar

   redrawscrollwin(princ,0);
   redrawscrollwin(winfo,0);
}

int check_pthread(void)
{
   int ris,i,ret;
   ris = i = ret = 0;

   if ( (sniff_glob || stream_glob || bc_glob || rst_glob || arp_glob) == 1)
     {
        lg = 0;
	pop_up_win();
	mvwprintw(pop_up,6,8,"Warning, another function is running!");
	mvwprintw(pop_up,7,11,"Should i stop its thread (y/n)?");
	wmove(pop_up,8,6);
	do
	  {
	     ris=wgetch(pop_up);
	     if (ris == 'y')
	       {
		  if(stream_glob) 
		  	{
		  	(i=0);
			pthread_cancel(thID[5]);
		  	pthread_join(thID[5], NULL);
		  	}
		  if(sniff_glob) (i=1);
		  if(rst_glob) (i=2);
		  if(arp_glob) (i=6);
		  if(bc_glob)
		    {
		       bc_glob=0;
		       pthread_cancel(pt[1]);
		       pthread_join(pt[1], NULL);
		       werase(winfo->win);
		       return(0);
		    }
		  stream_glob = sniff_glob = rst_glob = arp_glob = 0;
		  pthread_cancel(thID[i]);
		  pthread_join(thID[i], NULL);
		  winscroll(princ, -10000);
		  werase(princ->win);
		  ret = 0;
	       }

	     else if (ris == 'n')
	       {
		  delwin(pop_up);
		  pop_up_win();
		  mvwprintw(pop_up,6,8,"I will continue with the old function");
		  ret = 1;
	       }
	  }
	while( ris != 'y' && ris != 'n');
	delwin(pop_up);
	redrawscrollwin(princ,0);
     }
   return(ret);
}

int n_error(char *err, int fatal)
{
   int ris;
   ris = 0;

   if(fatal)
     {
	endwin();
	fprintf(stderr, "\n%s\n\n", err);
	exit(-1);
     }
   else
     {
	pop_up_win();
	mvwprintw(pop_up,6,3,"%s",err);
	mvwprintw(pop_up,12,18,"Press 'q' to quit");
	do
	  {
	     ris=wgetch(pop_up);
	  }
	while( ris != 'q');
	delwin(pop_up);
	werase(princ->win);
	redrawscrollwin(princ,0);
	return(0);
     }

}

int shutdown_thread(void)
{
   int ris,i,ret;
   ris = i = ret = 0;

   if ( (sniff_glob || stream_glob || bc_glob || rst_glob || arp_glob) == 1)
     {
	if(bc_glob)
	  {
	     bc_glob=0;
	     werase(princ->win);
	     werase(winfo->win);
	     pthread_cancel(pt[1]);
	     pthread_join(pt[1], NULL);
	     return(0);
	  }
	if(stream_glob)
	  {
	     (i=3);
	     stream_glob=0;
	     werase(princ->win);
	     werase(winfo->win);
	     pthread_cancel(thID[5]);
	     pthread_join(thID[5],NULL);
	     pthread_cancel(thID[i]);
	     pthread_join(thID[i], NULL);
	     return(0);
	  }

	if(sniff_glob)
	  {
	     (i=1);
	     sniff_glob=0;
	     werase(princ->win);
	     werase(winfo->win);
	     redrawscrollwin(winfo,0);
	     pthread_cancel(thID[i]);
	     pthread_join(thID[i], NULL);
	     return(0);
	  }

	if(rst_glob)
	  {
	     (i=2);
	     rst_glob=0;
	     werase(princ->win);
	     werase(winfo->win);
	     redrawscrollwin(winfo,0);
	     pthread_cancel(thID[i]);
	     pthread_join(thID[i], NULL);
	     return(0);
	  }
	if(arp_glob)
	  {
	     (i=6);
	     arp_glob=0;
	     werase(princ->win);
	     werase(winfo->win);
	     redrawscrollwin(winfo,0);
	     pthread_cancel(thID[i]);
	     pthread_join(thID[i], NULL);
	     return(0);
	  }
     }

   return(0);
}

#endif

