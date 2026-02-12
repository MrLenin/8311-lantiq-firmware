/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#ifdef LINUX

#include <assert.h>
#include <memory.h>
#include <sys/ioctl.h>
#include <sys/select.h>

#include "tui.h"
#include "optic_top.h"

#ifndef WITH_CURSES
#include <termios.h>

static struct termios orig_opts;

volatile int rows, cols;

void initscr ( void )
{
	int c, r;
	terminalsize_get(&c, &r);
	resize_term(r, c);
}

void endwin ( void )
{
	tcsetattr(STDIN_FILENO, TCSANOW, &orig_opts);
}

void cbreak ( void )
{
	struct termios opts;
	int res = 0;

	res = tcgetattr(STDIN_FILENO, &orig_opts);
	assert(res == 0);

	memcpy(&opts, &orig_opts, sizeof(opts));
	opts.c_cc[VMIN] = 1;
	opts.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON | IEXTEN |
	                  ICRNL);
	tcsetattr(STDIN_FILENO, TCSANOW, &opts);
}

int getch ( void )
{
	char c = 10;

	if (!read(0, &c, 1))
		return 0;

	if (c == '\033') {
		if (!read(0, &c, 1))
			return 0;

		if (c != '[')
			return 0;

		if (!read(0, &c, 1))
			return 0;

		/* suitable for PuTTY default settings; need to fix if other
		 * escase sequences are to be used */
		switch (c) {
		case 'A':
			return KEY_UP;
		case 'B':
			return KEY_DOWN;
		case 'C':
			return KEY_RIGHT;
		case 'D':
			return KEY_LEFT;
		case '1':
			read(0, &c, 1);
			return KEY_HOME;
		case '4':
			read(0, &c, 1);
			return KEY_END;
		case '5':
			read(0, &c, 1);
			return KEY_PPAGE;
		case '6':
			read(0, &c, 1);
			return KEY_NPAGE;
		default:
			return 0;
		}
	}

	return (int)c;
}

void attron ( int attr )
{
	switch (attr) {
	case A_UNDERLINE:
		printf("\033[4m");
		break;
	case A_STANDOUT:
		printf("\033[1m");
		break;
	}
}

void attroff ( int attr )
{
	switch (attr) {
	case A_UNDERLINE:
	case A_STANDOUT:
		printf("\033[0m");
		break;
	}
}

void resize_term ( int lines, int columns )
{
	rows = lines;
	cols = columns;
}
#endif

void terminalsize_get ( int *col, int *row )
{
	struct winsize win_size = { 0, 0, 0, 0 };

	*col = 80;
	*row = 48;

	if (ioctl(0, TIOCGWINSZ, &win_size))
		return;

	if (win_size.ws_col)
		*col = win_size.ws_col;

	if (win_size.ws_row)
		*row = win_size.ws_row;
}

int key_read ( void )
{
	fd_set rfds;
	struct timeval tv;

	FD_ZERO(&rfds);
	FD_SET(0, &rfds);

	tv.tv_sec = 0;
	tv.tv_usec = 100;

	if (select(1, &rfds, 0, 0, &tv))
#ifndef WITH_CURSES
		/* for proper resize handling */
		if (select(1, &rfds, 0, 0, &tv))
#endif
			return getch();

	return 0;
}

#endif
