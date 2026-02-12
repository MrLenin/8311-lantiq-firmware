/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/
#ifndef __tui_h
#define __tui_h

/** "Ctrl-A" key definition */
#define KEY_CTRL_A 1

/** "Ctrl-D" key definition */
#define KEY_CTRL_D 4

/** "Ctrl-E" key definition */
#define KEY_CTRL_E 5

/** "Ctrl-F" key definition */
#define KEY_CTRL_F 6

/** "Ctrl-H" key definition */
#define KEY_CTRL_H 8

/** "Ctrl-U" key definition */
#define KEY_CTRL_U 21

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

#if defined(LINUX)
#  include <stdio.h>
#  include <termios.h>
#  include <unistd.h>
#endif

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

extern volatile int rows, cols;

/** Set cursor position to (X; Y) */
#  define move(y, x) printf("\033[%d;%dH", (unsigned int) (y + 1), (unsigned int) (x + 1))

/** Returns width of the window */
#  define getmaxx(scr) cols

/** Returns height of the window */
#  define getmaxy(scr) rows

/** Standard screen

   \note dummy
*/
#  define stdsrc 0

/** Print char */
#  define addch(ch) printf("%c", ch)

/** Clear the window */
#  define clear() printf("\033[2J")

/** Move cursor and print string */
#  define mvaddstr(y, x, str) \
	do { \
		move(y,x); \
		printf(str); \
	} while (0)

/** Print formatted string */
#  define printw printf

/** Update the display immediately */
#  define refresh() fflush(stdout)

/** Print string */
#  define addstr(str) printf(str)

/** Generate escape sequences for some keys

   \note dummy
*/
#  define keypad(scr, flag) do {} while(0) /* nothing */

/** Leave newline mode

   \note dummy
*/
#  define nonl() do {} while(0) /* nothing */

/** Leave echo mode

   \note dummy
*/
#  define noecho() do {} while(0) /* nothing */

/** Clear to the end of line */
#  define clrtoeol() printf("\033[K");

/** Set the cursor state
   \param[in] flag - 0 hide cursor
                   - 1 show cursor
*/
#  define curs_set(flag) \
   do { \
      if ((flag) == 0) \
         printf("\033[?25l"); \
      else \
         printf("\033[?25h"); \
   } while (0)

/** Initialize the library */
void initscr ( void );

/** Get a character */
int getch ( void );

/** Enter cbreak mode (turn off line buffering) */
void cbreak ( void );

/** De-initialize the library, and return terminal to normal status */
void endwin ( void );

/** Print underlined text */
#define A_UNDERLINE 0

/** Print bright text */
#define A_STANDOUT 1

/** Enable attribute
   \param[in] attr Attribute
*/
void attron ( int attr );

/** Disable attribute
   \param[in] attr Attribute
*/
void attroff ( int attr );

/** Resize terminal

   \param[in] lines New lines number
   \param[in] columns New columns number
*/
void resize_term ( int lines, int columns );
#endif

/** Get terminal size

   \param[out] col Columns number
   \param[out] row Rows (lines) number
*/
void terminalsize_get ( int *col, int *row );

/** Non-blocking getch

   \return Key index or 0 if no key
*/
int key_read ( void );

#endif
