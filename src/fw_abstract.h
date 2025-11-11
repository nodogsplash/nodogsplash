
#ifndef _FW_ABSTRACT_H_
#define _FW_ABSTRACT_H_

#include <stdint.h>
#include <time.h>

#include "fw_iptables.h"

typedef struct {
  int (*init)(void);
  int (*destroy)(void);
  int (*authenticate)(t_client *client);
  int (*deauthenticate)(t_client *client);
  unsigned long long int (*total_download)();
  unsigned long long int (*total_upload)();
  int (*counters_update)(void);
  const char *(*connection_state_as_string)(int mark);
  int (*do_command)(const char format[], ...);
  int (*block_mac)(const char mac[]);
  int (*unblock_mac)(const char mac[]);
  int (*allow_mac)(const char mac[]);
  int (*unallow_mac)(const char mac[]);
  int (*trust_mac)(const char mac[]);
  int (*untrust_mac)(const char mac[]);
} fw_ops;

extern fw_ops fw_gops;

void fw_use_iptables();

#endif /* _FW_ABSTRACT_H_ */

