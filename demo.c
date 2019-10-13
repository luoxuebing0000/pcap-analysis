#include "pcap.h"
#include "filter.h"
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <string.h>
#include "mymemory.h"

//---------------------------------------------------------------------------
//  方案1
//---------------------------------------------------------------------------

int main(int argc, char *argv[])
{
	const char* filepath = argv[1];
	const char* filter_condition = argv[2];

	pcap_fd_st* pcap_fd = pcap_reader_init(filepath);
	filter_fd_st* filter_fd = filter_creat(filter_condition);

	char* buf = NULL;
	int buflen = 0;

	while (pcap_reader_getpkt(pcap_fd, &buf, &buflen) == 0) {
		packet_st* packet = pcap_parse(buf, buflen);
		
		if (filter_math(filter_fd, packet) == 0) {
			pcap_dump(packet);
		}

		free(buf);
		buf = NULL;
		buflen = 0;
		pcap_parse_release(packet);
	}

	filter_release(filter_fd);
	pcap_reader_release(pcap_fd);
    return 1;
}
