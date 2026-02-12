/******************************************************************************

                               Copyright (c) 2010
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef __tui_h
#define __tui_h

/** "Ctrl-A" key definition */
#define KEY_CTRL_A 1

/** "Ctrl-B" key definition */
#define KEY_CTRL_B 2

/** "Ctrl-D" key definition */
#define KEY_CTRL_D 4

/** "Ctrl-E" key definition */
#define KEY_CTRL_E 5

/** "Ctrl-F" key definition */
#define KEY_CTRL_F 6

/** "Ctrl-H" key definition */
#define KEY_CTRL_H 8

/** "Ctrl-R" key definition */
#define KEY_CTRL_R 18

/** "Ctrl-U" key definition */
#define KEY_CTRL_U 21

/** "Ctrl-V" key definition */
#define KEY_CTRL_V 22

/** "Ctrl-W" key definition */
#define KEY_CTRL_W 23

/** "Ctrl-X" key definition */
#define KEY_CTRL_X 24

/** "Ctrl-Y" key definition */
#define KEY_CTRL_Y 25

/** "Backspace 2" key definition (used by default in PuTTY) */
#  define KEY_BACKSPACE2 127

#ifdef WITH_CURSES
#  include <curses.h>

#  undef  KEY_ENTER
/** "Enter" key definition */
#  define KEY_ENTER 13

#else
#  include <stdio.h>
#  include <stdarg.h>
#  include <termios.h>
#  include <unistd.h>

/** "Enter" key definition */
#  define KEY_ENTER 10

/** "Backspace" key definition */
#  define KEY_BACKSPACE 8

/** "Arrow up" key definition */
#  define KEY_UP 0403

/** "Arrow down" key definition */
#  define KEY_DOWN 0402

/** "Arrow left" key definition */
#  define KEY_LEFT 0404

/** "Arrow right" key definition */
#  define KEY_RIGHT 0405

/** "Page up" key definition */
#  define KEY_PPAGE 0523

/** "Page down" key definition */
#  define KEY_NPAGE 0522

/** "Home" key definition */
#  define KEY_HOME 0406

/** "End" key definition */
#  define KEY_END 0550

extern volatile unsigned int g_rows, g_cols;

/** Standard screen

   \note dummy
*/
#  define stdscr	0

/** 'TRUE' definition */
#  define TRUE		1

/** Set cursor position to (X; Y) */
static inline void move(int y, int x)
{
	(void)fprintf(stdout, "\033[%d;%dH", y + 1, x + 1);
}

/** Returns width of the window */
static inline unsigned int getmaxx(int scr)
{
	return g_cols;
}

/** Returns height of the window */
static inline unsigned int getmaxy(int scr)
{
	return g_rows;
}

/** Print string */
void addstr(const char *s);

/** Clear the window */
static inline void clear(void)
{
	addstr("\033[2J");
}

/** Move cursor and print string */
static inline void mvaddstr(unsigned int y, unsigned int x, const char *s)
{
	move(y, x);
	addstr(s);
}

/** Print formatted string */
static inline int printw(const char *format, ...)
{
	va_list arg;
	int ret;

	va_start(arg, format);
	ret = vfprintf(stdout, format, arg);
	va_end(arg);

	return ret;
}

/** Update the display immediately */
static inline void refresh(void)
{
	fflush(stdout);
}

/** Generate escape sequences for some keys

   \note dummy
*/
static inline void keypad(int scr, int flag) { }

/** Leave newline mode

   \note dummy
*/
static inline void nonl(void) { }

/** Leave echo mode

   \note dummy
*/
static inline void noecho(void) { }

/** Clear to the end of line */
static inline void clrtoeol(void)
{
	addstr("\033[K");
}

/** Clear to the end of the screen */
static inline void clrtobot(void)
{
	addstr("\033[J");
}

/** Set the cursor state
   \param[in] flag - 0 hide cursor
                   - 1 show cursor
*/
static inline void curs_set(int flag)
{
	switch(flag) {
	case 0:
		addstr("\033[?25l");
		break;
	case 1:
		addstr("\033[?25h");
		break;
	default:
		break;
	}

}

/** Initialize the library */
int initscr(void);

/** Get a character */
int getch(void);

/** Enter cbreak mode (turn off line buffering) */
void cbreak(void);

/** De-initialize the library, and return terminal to normal status */
void endwin(void);

/** Print underlined text */
#define A_UNDERLINE 0

/** Print bright text */
#define A_STANDOUT 1

/** Enable attribute
   \param[in] attr Attribute
*/
void attron(int attr);

/** Disable attribute
   \param[in] attr Attribute
*/
void attroff(int attr);

/** resize terminal

   \param[in] lines New lines number
   \param[in] columns New columns number
*/
void resizeterm(unsigned int lines, unsigned int columns);
#endif

/** Get terminal size

   \param[out] cols Columns number
   \param[out] rows Rows (lines) number
*/
void terminal_size_get(unsigned int *cols, unsigned int *rows);

/** Non-blocking getch

   \return Key index or 0 if no key
*/
int key_read(void);

#endif
