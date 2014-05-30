#ifndef _JSP_SERVER_H_
#define _JSP_SERVER_H_

#include "or1k_tap.h"
#include "or1k.h"
#include "or1k_du.h"

#include <server/server.h>

#define TELNET_BUFFER_SIZE (1024)

#define TELNET_OPTION_MAX_SIZE (128)
#define TELNET_LINE_HISTORY_SIZE (128)
#define TELNET_LINE_MAX_SIZE (256)

enum telnet_states {
	TELNET_STATE_DATA,
	TELNET_STATE_IAC,
	TELNET_STATE_SB,
	TELNET_STATE_SE,
	TELNET_STATE_WILL,
	TELNET_STATE_WONT,
	TELNET_STATE_DO,
	TELNET_STATE_DONT,
	TELNET_STATE_ESCAPE,
};

struct telnet_connection {
	char *prompt;
	enum telnet_states state;
	char line[TELNET_LINE_MAX_SIZE];
	int line_size;
	int line_cursor;
	char option[TELNET_OPTION_MAX_SIZE];
	int option_size;
	char last_escape;
	char *history[TELNET_LINE_HISTORY_SIZE];
	int next_history;
	int current_history;
	int closed;
};

struct jsp_service {
	char *banner;
	struct or1k_jtag *jtag_info;
	struct connection *connection;
};

int jsp_init(struct or1k_jtag *jtag_info, char *banner);
int jsp_register_commands(struct command_context *cmd_ctx);

#endif	/* _JSP_SERVER_H_ */
