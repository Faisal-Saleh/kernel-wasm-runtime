
#ifndef rtt_config_h
#define rtt_config_h

extern char *server_ip;
extern char *client_ip;
extern unsigned short server_port;
extern unsigned short client_port;

int send_rtt_init(void);
void send_rtt_exit(void);
int pong_rtt_init(void);
void pong_rtt_exit(void);

#endif
