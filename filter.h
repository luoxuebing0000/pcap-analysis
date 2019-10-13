#ifndef FILTER_H_
#define FILTER_H_

#include "pcap.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _filter_fd_st filter_fd_st;

/* ¹ıÂËÆ÷ */
filter_fd_st *filter_creat(const char *filter_condition);
void filter_release(filter_fd_st* filter_fd);

int filter_math(filter_fd_st* filter_fd, packet_st* packet);


#ifdef __cplusplus
}
#endif

#endif //FILTER_H_
