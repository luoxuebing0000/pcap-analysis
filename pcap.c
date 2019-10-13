#include "pcap.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "mymemory.h"

/**
 *  PCAP文件的文件头
 */
typedef struct _pcap_file_header {
    __u32 magic;            //主标识:a1b2c3d4
    __u16 version_major;    //主版本号
    __u16 version_minor;    //次版本号
    __u32 thiszone;         //区域时间0
    __u32 sigfigs;          //时间戳0
    __u32 snaplen;          //数据包最大长度
    __u32 linktype;         //链路层类型，取值：DLT_*
} pcap_file_header;

/*
 * These are the types that are the same on all platforms, and that
 * have been defined by <net/bpf.h> for ages.
 */
#define DLT_NULL    0   /* BSD loopback encapsulation */
#define DLT_EN10MB  1   /* Ethernet (10Mb) */
#define DLT_EN3MB   2   /* Experimental Ethernet (3Mb) */
#define DLT_AX25    3   /* Amateur Radio AX.25 */
#define DLT_PRONET  4   /* Proteon ProNET Token Ring */
#define DLT_CHAOS   5   /* Chaos */
#define DLT_IEEE802 6   /* IEEE 802 Networks */
#define DLT_ARCNET  7   /* ARCNET, with BSD-style header */
#define DLT_SLIP    8   /* Serial Line IP */
#define DLT_PPP     9   /* Point-to-point Protocol */
#define DLT_FDDI    10  /* FDDI */


#ifdef __OpenBSD__
#define DLT_RAW     14  /* raw IP */
#else
#define DLT_RAW     12  /* raw IP */
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 0x6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 0x11
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 0x1
#endif

#define IPPROTO     0x800

#define IP_LEN			16  /* ip长度 */
#define NET_FRAME_LEN	14  /* 以太网帧头长度 */
#define OUT_STR_LEN		100 /* 要输入的信息长度 */

/**
 *  PCAP文件中数据包所使用的时间戳
 */
typedef struct _pcap_time_stamp {
    __u32 tv_sec;
    __u32 tv_usec;
} pcap_time_stamp;

/**
 *  PCAP文件中数据包的头部
 */
typedef struct _pcap_pkthdr {
    pcap_time_stamp ts;
    __u32 caplen;
    __u32 len;
} pcap_pkthdr;


/* 读取器 */
struct _pcap_fd_st {
	FILE* fs_fd;				/* 传入的pcap文件句柄 */
	pcap_file_header fs_head;   /* pcap文件头信息 */
};

struct IP_HEAD
{
	unsigned char verhlen;  // :4位version, 4位len (<<2) 45H
	unsigned char tos;      // 服务,优先级，正常设为0
	unsigned short len;     // 长度，以字节表示数据报总长度，包括IP 报文头
	unsigned short ident;   // 标识
	unsigned short frags;   // 分段
	unsigned char ttl;      // 生存时间,典型值：100 秒
	unsigned char procotol; // 协议 ,数据域所用协议，比如：1-ICMP 6-TCP，0x11-UDP
	unsigned short crc;     // 校验和,仅仅是IP 头的简单校验和
	unsigned int srcip;     // 4 字节源IP 地址
	unsigned int dstip;     // 4 字节目的IP 地址
};

struct TCP_HEAD
{
	unsigned short srcport; //源端口
	unsigned short dstport; //目标端口
	unsigned int seq;
	unsigned int ack;
	unsigned char hlen;     //头部长度
	char notcare[0];        //不关心
};

struct UDP_HEAD
{
	unsigned short srcport;
	unsigned short dstport;
	unsigned short len;
	unsigned short crc;
};

struct _packet_st {
	unsigned int buflen;	/* 每一个读取器读取的缓冲区数据 */
	char* buf;				/* 缓冲区数据大小 */
};

/* 读取数据宏 */
#define READ_CACHE(buf, buflen, fd) do { \
	size_t ret = 0; \
	ret = fread(buf, 1, buflen, fd); \
	if (ret != buflen) { \
		printf("read file error, buflen = %ld\n", ret); \
		goto _ERROR_OCUR_; \
	} \
}while (0); \

pcap_fd_st* pcap_reader_init(const char* filepath)
{
	if (filepath == NULL)
		return NULL;

	pcap_fd_st* pcap_fd = (pcap_fd_st*)zero_alloc(sizeof(pcap_fd_st));

	pcap_fd->fs_fd = fopen(filepath, "rb+");
	if (pcap_fd->fs_fd == NULL) {
		printf("open file %s failed\n", filepath);
		goto _ERROR_OCUR_;
	}

	/* 读取文件头信息 */
	READ_CACHE(&pcap_fd->fs_head, (sizeof(pcap_fd->fs_head)), pcap_fd->fs_fd);

	return pcap_fd;

_ERROR_OCUR_:
	pcap_reader_release(pcap_fd);
	return NULL;
}

void pcap_reader_release(pcap_fd_st* pcap_fd)
{
	if (pcap_fd == NULL)
		return;

	if (pcap_fd->fs_fd)
		fclose(pcap_fd->fs_fd);
	if (pcap_fd)
		free(pcap_fd);
}

int pcap_reader_getpkt(pcap_fd_st* pcap_fd, char** buf, int* bufsize)
{
	if (pcap_fd == NULL || buf == NULL || bufsize == NULL) {
		printf("param error, can't be NULL\n");
		return -1;
	}

	if (feof(pcap_fd->fs_fd))  // 文件读取结束
		return 1;

	pcap_pkthdr* pkthdr = (pcap_pkthdr*)zero_alloc(sizeof(pcap_pkthdr));
	READ_CACHE(pkthdr, (sizeof(pcap_pkthdr)), pcap_fd->fs_fd);

	char* tmpbuf = zero_alloc(pkthdr->caplen);
	
	*bufsize = pkthdr->caplen;
	READ_CACHE(tmpbuf, pkthdr->caplen, pcap_fd->fs_fd);

	*buf = tmpbuf;

	return 0;

_ERROR_OCUR_:
	return -1;
}

packet_st* pcap_parse(const char *buf, int bufsize)
{
	if (buf == NULL || bufsize <= 0)
		return NULL;

	packet_st* packet = (packet_st*)zero_alloc(sizeof(packet_st));
	
	packet->buf = (char*)zero_alloc(bufsize);
	memcpy(packet->buf, buf, bufsize);
	packet->buflen = bufsize;

	return NULL;
}

void pcap_parse_release(packet_st* packet)
{
	if (packet == NULL)
		return;
	if (packet->buf)
		free(packet->buf);
	free(packet);
}

static void toStringIP(const unsigned int ip, char* stringIP)
{
	unsigned int tempIP = ip;

	for (int i = 0; i < 3; i++) {
		unsigned char part = (char)tempIP;
		char temp[4] = { 0 };
		sprintf(temp, "%d.", part);
		strcat(stringIP, temp);
		tempIP = tempIP >> 8;
	}
	unsigned char part = (char)tempIP;
	char temp[4];
	sprintf(temp, "%d", part);
	strcat(stringIP, temp);
}

void pcap_dump(packet_st* packet)
{
	if (packet == NULL)
		return;

	int offset = NET_FRAME_LEN;
	char* src_ip = NULL; // 源IP
	char* dst_ip = NULL; // 目的IP
	char outstr[OUT_STR_LEN] = { 0 };

	struct IP_HEAD* ip_head = (struct IP_HEAD*)zero_alloc(sizeof(struct IP_HEAD));

	ip_head = (struct IP_HEAD*)(packet->buf + offset);

	src_ip = (char*)zero_alloc(IP_LEN + 1);
	toStringIP(ip_head->srcip, src_ip);

	dst_ip = (char*)zero_alloc(IP_LEN + 1);
	toStringIP(ip_head->dstip, dst_ip);

	offset += sizeof(struct TCP_HEAD);
	
	if (ip_head->procotol == IPPROTO_ICMP) {	 // ICMP
		printf("Procotol: ICMP\n");
	}
	else if (ip_head->procotol == IPPROTO_TCP) { // TCP
		
		struct TCP_HEAD* tcp_head = (struct TCP_HEAD*)zero_alloc(sizeof(struct TCP_HEAD));
		tcp_head = (struct TCP_HEAD*)(packet->buf + offset);

		snprintf(outstr, OUT_STR_LEN - 1, "Procotol: TCP, SrcIP: %s, SrcPort: %d, DstIP: %s, DstPort: %d", src_ip, 
			tcp_head->srcport, dst_ip, tcp_head->dstport);

		free(tcp_head);
	}
	else if (ip_head->procotol == IPPROTO_UDP) { // UDP
		struct UDP_HEAD* udp_head = (struct UDP_HEAD*)zero_alloc(sizeof(struct UDP_HEAD));
		udp_head = (struct UDP_HEAD*)(packet->buf + offset);

		snprintf(outstr, OUT_STR_LEN - 1, "Procotol: TCP, SrcIP: %s, SrcPort: %d, DstIP: %s, DstPort: %d", src_ip,
			udp_head->srcport, dst_ip, udp_head->dstport);

		free(udp_head);
	}
	else {
		printf("uknow procotol\n");
	}

	if(outstr[0] != '\0')
		printf("%s\n", outstr);

	free(src_ip);
	free(dst_ip);
	free(ip_head);
}