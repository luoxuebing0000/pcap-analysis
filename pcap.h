#ifndef PCAP_H_
#define PCAP_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned char __u8;

typedef struct _packet_st packet_st;
typedef struct _pcap_fd_st pcap_fd_st;

/* 读取器 */

/**
 * 初始化读取器
 * @param: filepath pcap文件的路径
 * @return: pcap_fd句柄 若为NULL，则初始化失败
 */
pcap_fd_st* pcap_reader_init(const char* filepath);

/**
 * 释放读取器
 * @param: pcap_fd 读取器句柄
 * @return: 无
 */
void pcap_reader_release(pcap_fd_st* pcap_fd);

/**
 * 依次读取pcap数据，每调用依次读取依次，下次调用读取下一个数据
 * @param: pcap_fd 读取器句柄
 * @param: buf 函数内使用malloc分配内存，使用完使用free释放
 * @param: bufsize 读取的缓冲区数据大小
 * @return: 0 -> 表示成功  -1 -> 表示失败  1 -> 文件已读取完
 */
int pcap_reader_getpkt(pcap_fd_st* pcap_fd, char** buf, int* bufsize);

/* 解析器 */
/**
 * 解析pcap读取的数据
 * @param: buf 读取器每次读取到的数据缓冲区
 * @param：bufsize 读取器每次读取到的缓冲区数据大小
 * @return: 解析器句柄
 */
packet_st* pcap_parse(const char *buf, int bufsize);

/**
 * 打印解析器句柄数据
 * @param: packet 解析器句柄
 * @return: 无
 */
void pcap_dump(packet_st* packet);

/**
 * 释放解析器
 * @param: packet 解析器
 * @return: 无
 */
void pcap_parse_release(packet_st* packet);

#ifdef __cplusplus
}
#endif

#endif //PCAP_H_
