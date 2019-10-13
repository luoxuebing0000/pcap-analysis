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

/* ��ȡ�� */

/**
 * ��ʼ����ȡ��
 * @param: filepath pcap�ļ���·��
 * @return: pcap_fd��� ��ΪNULL�����ʼ��ʧ��
 */
pcap_fd_st* pcap_reader_init(const char* filepath);

/**
 * �ͷŶ�ȡ��
 * @param: pcap_fd ��ȡ�����
 * @return: ��
 */
void pcap_reader_release(pcap_fd_st* pcap_fd);

/**
 * ���ζ�ȡpcap���ݣ�ÿ�������ζ�ȡ���Σ��´ε��ö�ȡ��һ������
 * @param: pcap_fd ��ȡ�����
 * @param: buf ������ʹ��malloc�����ڴ棬ʹ����ʹ��free�ͷ�
 * @param: bufsize ��ȡ�Ļ��������ݴ�С
 * @return: 0 -> ��ʾ�ɹ�  -1 -> ��ʾʧ��  1 -> �ļ��Ѷ�ȡ��
 */
int pcap_reader_getpkt(pcap_fd_st* pcap_fd, char** buf, int* bufsize);

/* ������ */
/**
 * ����pcap��ȡ������
 * @param: buf ��ȡ��ÿ�ζ�ȡ�������ݻ�����
 * @param��bufsize ��ȡ��ÿ�ζ�ȡ���Ļ��������ݴ�С
 * @return: ���������
 */
packet_st* pcap_parse(const char *buf, int bufsize);

/**
 * ��ӡ�������������
 * @param: packet ���������
 * @return: ��
 */
void pcap_dump(packet_st* packet);

/**
 * �ͷŽ�����
 * @param: packet ������
 * @return: ��
 */
void pcap_parse_release(packet_st* packet);

#ifdef __cplusplus
}
#endif

#endif //PCAP_H_
