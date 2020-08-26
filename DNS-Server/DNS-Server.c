#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <time.h>
#include <stdint.h>

#ifdef _WIN32

#pragma comment(lib, "ws2_32.lib")
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <Windows.h>
// #define _WINSOCK_DEPRECATED_NO_WARNINGS
// #define _CRT_SECURE_NO_WARNINGS
// #define s_addr S_un.S_addr

#else

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <errno.h>

#endif


int debugLevel = 0;//0�����޵�����Ϣ��1������������Ϣ��2�������ӵ�����Ϣ
// char filename[100] = ".\dnsrelay.txt";
char filename[100] = "dnsrelay.txt";
char dns_server_ip[20] = "192.168.0.1";

#define BUFFER_SIZE 1024
#define PORT 53
#define PACKET_BUF_SIZE 4096 // 512字节（RFC1035规定），这个大小可以在互联网上畅通无阻，不会因为路径中某MTU（通常≥576（RFC791））太小而导致分片。

typedef struct DNSHEADER    //DNS报文报头字段
{
	unsigned short ID;      //2 bits
	unsigned short Flag;    //2 bits
	/*  Flag字段共包含以下几个字段
		QR：0表示查询报，1表示响应报。
		OPCODE：通常值为0（标准查询），其他值为1（反向查询）和2（服务器状态请求）。
		AA: 权威答案(Authoritative answer)
		TC: 截断的(Truncated)，应答的总长度超512字节时，只返回前512个字节
		RD: 期望递归(Recursion desired)，查询报中设置，响应报中返回，告诉名字服务器处理递归查询。如果该位为0，且被请求的名字服务器没有一个权威回答，就返回一个能解答该查询的其他名字服务器列表，这称为迭代查询
		RA：递归可用(Recursion Available)，如果名字服务器支持递归查询，则在响应中该比特置为1
		Z：必须为0，保留字段
		RCODE: 响应码(Response coded)，仅用于响应报
			值为0(没有差错)
			值为3表示名字差错。从权威名字服务器返回，表示在查询中指定域名不存在

	*/
	unsigned short QDCount; //2 bits
	unsigned short ANCount; //2 bits
	unsigned short NSCount; //2 bits
	unsigned short ARCount; //2 bits
} dnsHeader;

typedef struct DNSQUERY
{
	char* Qname;            //查询域名
	unsigned short Qtype;   //2 bits
	/*
	A(1) : IPv4
	AAAA(28) : IPv6
	*/
	unsigned short Qclass;  //IN(1), 2 bits
} dnsQuery;

typedef struct DNSRR
{
	char* Name;             //restore Domain Name
	unsigned short Type;    //2 bits
	unsigned short Class;   //2 bits
	unsigned int TTL;       //4 bits
	unsigned short RDLength;//2 bits
	char* RData;            //restore IP address
} dnsRR;


int lookUpTxt(char* DN, char* IP)
{
	int flag = 0;
	FILE* file;
    char txtInfo[BUFFER_SIZE];      //restore one line of txt
	char IPaddr[BUFFER_SIZE];       //restore IP address
	char domainName[BUFFER_SIZE];   //restore domain name

	if ((file = fopen(filename, "r")) == NULL)
    {
		printf("file open error\n");
		exit(1);
	}

    while(!feof(file))
    {
        fgets(txtInfo, BUFFER_SIZE, file);      //read one line of txt
        for(int i = 0; i < BUFFER_SIZE; i++)
        {
            if(txtInfo[i] == ' ')               //split IP from domain name
            {
                txtInfo[i] = '\0';
                IPaddr[i] = txtInfo[i];
                break;
            }
            IPaddr[i] = txtInfo[i];
        }

        strcpy(domainName, txtInfo + strlen(IPaddr) + 1);   //get domain Name
        if (domainName[strlen(domainName) - 1] == '\n')
            domainName[strlen(domainName) - 1] = '\0';
        else
            domainName[strlen(domainName)] = '\0';

        if( strcmp( DN, domainName ))         
		//If domain name can be found in txt, we should give the following IP address
        {
			char* temp = IPaddr;
			char* transform = IPaddr;
			int i = 0;
			while (*temp != '\0')
			{
				if (*temp == '.')
				{
					*temp = '\0';
					IP[i] = (char)atoi(transform);
					i++;
					transform = temp + 1;
				}
				temp++;
			}
			IP[i] = (char)atoi(transform);
			flag = 1;
        }
    }
	return flag;
}

void DNS_Server()
{
	char* DN, * IP;
	if (lookUpTxt(DN, IP))						//若在表中
	{
		if (IP[0] == (char)0 && IP[1] == (char)0 && IP[2] == (char)0 && IP[3] == (char)0)		//若IP为0.0.0.0
		{

		}
		else         //若IP不为0.0.0.0
		{
					
		}
	}
	else      //若不在表中，需要上传给Internet DNS服务器
	{

	}
}

void initCommand(int argc, char* argv[])
{
    int count = 1;
    for (count = 1; count < argc; ++count) 
    {
        if (strcmp(argv[count], "-d") == 0)
            debugLevel = 1;
        else if (strcmp(argv[count], "-dd") == 0)
            debugLevel = 2;
        else
        {
            int i = 0;
            int flag = 0;
            while (argv[count][i])
            {
                if (strcmp(&argv[count][i], ".txt") == 0)
                {
                    // strcpy_s(filename, sizeof(filename), argv[count]);
                    strncpy(filename, argv[count], sizeof(filename));
                    flag = 1;
                    break;
                }
                i++;
            }
            if (flag == 0)
                // strcpy_s(dns_server_ip, sizeof(dns_server_ip), argv[count]);
                strncpy(dns_server_ip, argv[count], sizeof(dns_server_ip));
        }
    }
    printf("debuglevel:%d\n", debugLevel);
    // TODO: 缺少IP合法性的判断
    printf("dns_server_ip:%s\n", dns_server_ip);
    printf("filename:%s\n", filename);
}

int initSock(){
    /* 创建 socket 对象
        AF_INET: 因特网 TCP/IP 地址族 (TODO: IPv4网络？？)
        SOCK_DGRAM: 以数据报为传输形式
        IPPROTO_UDP: 采用 UDP 协议
        (均为socket相关头文件中所定义的常量)
    */
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    /* 创建 socket 网络通信对象
        typedef struct sockaddr_in {
            ADDRESS_FAMILY sin_family; // 地址族
            USHORT sin_port; // 端口号 (注: 网络字节顺序)
            IN_ADDR sin_addr; // IP地址 (注: 网络字节顺序)
            CHAR sin_zero[8]; // 保留的空字节 (为使结构体 sockaddr_in 与 sockaddr 大小相同，以便相互转换)
        }

        INADDR_ANY: (unsigned long)0x00000000  即网络字节顺序的IP地址 0.0.0.0
    */
	struct sockaddr_in sockAddr;
    socklen_t sockLen = sizeof(struct sockaddr_in);
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = htons(PORT);
	sockAddr.sin_addr.s_addr = INADDR_ANY;
    // sockaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	
    // 绑定 socket 对象与 socket 网络通信对象
    // 调试中遇到的问题+1，无法绑定53端口，svchost端口占用kill即可
    // 调试中遇到的问题+1，无法绑定53端口，加上WSA
    int bindRet = bind(sockfd, (struct sockaddr*) &sockAddr, sockLen);
    if (bindRet < 0)
    {
		printf("Fail to bind port %d\n", PORT);
		exit(1);
	}
    else
    {
        printf("Successfully bound port %d\n", PORT);
    }

    return sockfd;
}

void printPacket (const char *szPrefix, struct sockaddr_in *sa, char *pbBuf, int bufLen, char mode){
    // Print prefix, ip addr, port and buffer length
    printf ("%s %s:%d (%d bytes) ", szPrefix, inet_ntoa (sa->sin_addr), ntohs (sa->sin_port), bufLen);

    // mode 1 is simplified logging
    if (mode == 2) return;

    // Print raw buffer
    for (int i = 0; i < bufLen; ++i) printf (" %02x", pbBuf[i]);

    // Print packet content
    int *pwBuf = (int *) pbBuf;
    int flags = ntohs (pwBuf[1]);

    printf ("\n\tID %04x, QR %d, OPCODE %d, AA %d, TC %d, RD %d, RA %d, Z %d, RCODE %d\n"
            "\tQDCOUNT %u, ANCOUNT %u, NSCOUNT %u, ARCOUNT %u\n",
            ntohs (pwBuf[0]),
            (int) ((flags & 0x8000) >> 15),
            (int) ((flags & 0x7800) >> 11),
            (int) ((flags & 0x0400) >> 10),
            (int) ((flags & 0x0200) >> 9),
            (int) ((flags & 0x0100) >> 8),
            (int) ((flags & 0x0080) >> 7),
            (int) ((flags & 0x0070) >> 4),
            (int) ((flags & 0x000F) >> 0),
            ntohs (pwBuf[2]),
            ntohs (pwBuf[3]),
            ntohs (pwBuf[4]),
            ntohs (pwBuf[5]));
}
	
void recvPaket(int* bufLen, int sockfd, char* buf, int packetSize, struct sockaddr_in* sockFrom, socklen_t* sockLen){
    *bufLen = recvfrom(sockfd, (char*) buf, packetSize, 0, (struct sockaddr *) sockFrom, sockLen);
}

void InitWSA ()
{
#ifdef WIN32
	// Init WSA on Windows
	struct WSAData WSAData;
	if (WSAStartup (MAKEWORD (2, 2), &WSAData))
	{
		printf ("WSAStartup() error\n");
		exit (1);
	}
#endif
}

int main(int argc, char* argv[]) 
{
    initCommand(argc, argv);
    
    InitWSA ();
    // 创建 socket 对象并初始化
    int sockfd = initSock();

    // 客户端网络通信对象
    struct sockaddr_in sockFrom;
    socklen_t sockLen = sizeof(struct sockaddr_in);
    while(1){
        char buf[PACKET_BUF_SIZE];
        int bufLen;
        recvPaket(&bufLen, sockfd, buf, PACKET_BUF_SIZE, &sockFrom, &sockLen);
        printPacket("RECV from", &sockFrom, buf, bufLen, 1);
    }
    
    // close(sockfd);
    return 0;
}