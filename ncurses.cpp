#include "ncurses.h"

WINDOW *my_win;
int startx, starty, width, height;

bool color_supported = true;

WINDOW *create_newwin(int height, int width, int starty, int startx)
{	WINDOW *local_win;

	local_win = newwin(height, width, starty, startx);
	box(local_win, 0 , 0);		/* 0, 0 gives default characters 
					 * for the vertical and horizontal
					 * lines			*/
	wrefresh(local_win);		/* Show that box 		*/

	return local_win;
}

void init_ncurses()
{
	initscr();                      /* Start curses mode              */
        if(has_colors() == FALSE)
        {
            color_supported = false;
        }
        else
        {
            color_supported = true;
            start_color();
            init_pair(1, COLOR_RED, COLOR_BLACK);//zigbee colors
            init_pair(2, COLOR_BLUE, COLOR_BLACK);//bt colors
        }
	height = LINES;
	width = COLS;
	starty = (LINES - height) / 2;	/* Calculating for a center placement */
	startx = (COLS - width) / 2;	/* of the window		*/
	//printw("Press F1 to exit");
	refresh();
	my_win = create_newwin(height, width, starty, startx);
	n_draw_border();
}
void end_ncurses()
{
    endwin();                       /* End curses mode                */
}

void n_draw_border()
{
	wborder(my_win, '|', '|', '-', '-', '+', '+', '+', '+');
	wrefresh(my_win);
	print_headers();
        wrefresh(my_win);
}

void print_ncurses(int line_num,char * txt)
{
	int y = line_num;
	int x = 1;
	wmove(my_win, y, x);
	waddstr(my_win,txt);
	wrefresh(my_win);
}

void print_headers()
{
	wmove(my_win,1,1);
	waddstr(my_win,"Device");
	wmove(my_win,1,15);
	waddstr(my_win,"Chan");
        wmove(my_win,1,25);
        waddstr(my_win,"Pkts");
        wmove(my_win,1,35);
        waddstr(my_win,"Errors");
}

void print_status(int y,int type,int chan,int pkt_cnt,int error_cnt)
{
    char t_type[14];memset(t_type,0x00,14);
    if(type == 1)//CC2531
        snprintf(t_type,14,"CC2531");
    else if(type == 2)//CC2540
        snprintf(t_type,14,"CC2540");
    else
        snprintf(t_type,14," ");

    if(color_supported && type == 1)
    {
        init_pair(1, COLOR_RED, COLOR_BLACK);//zigbee colors
        attron(COLOR_PAIR(1));
    }
    else if(color_supported && type == 2)
    {
        init_pair(2, COLOR_BLUE, COLOR_BLACK);//bt colors
        attron(COLOR_PAIR(2));
    }


	wmove(my_win,y,1);
	waddstr(my_win,t_type);

    char t_chan[10];memset(t_chan,0x00,10);
    snprintf(t_chan,10,"%d",chan);
    wmove(my_win,y,15);
    waddstr(my_win,t_chan);

    char t_pkt[10];memset(t_pkt,0x00,10);
    snprintf(t_pkt,10,"%d",pkt_cnt);
    wmove(my_win,y,25);
    waddstr(my_win,t_pkt);

    char t_epkt[10];memset(t_epkt,0x00,10);
    snprintf(t_epkt,10,"%d",error_cnt);
    wmove(my_win,y,35);
    waddstr(my_win,t_epkt);
    wrefresh(my_win);
    if(color_supported && type == 1)
    {
        attroff(COLOR_PAIR(1));
    }
    else if(color_supported && type == 2)
    {
        attroff(COLOR_PAIR(2));
    }
}

void print_running_status(bool running)
{

    int x = 1;
    int y = LINES - 3;

    wmove(my_win,y,x);
    if(running)
        waddstr(my_win,"running");
    else
        waddstr(my_win,"shutting down");

    y = LINES - 2;
    wmove(my_win,y,x);
    waddstr(my_win,"Press Ctrl+C to exit");

    wrefresh(my_win);
}

void print_time()
{
    char real_time[64];
    time_t rawtime;
    struct tm * timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    snprintf(real_time,64,"%s",asctime(timeinfo));
    int timelen = strlen(real_time);
    real_time[timelen] = 0;
    real_time[timelen-1] = 0;

    int x = COLS;
    int y = LINES - 2;
    x = x - timelen;

    wmove(my_win,y,x);
    waddstr(my_win,real_time);

    wrefresh(my_win);
}
