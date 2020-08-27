#define  _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
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

#define RECORD_SIZE 4096
#define BUFFER_SIZE 1024
#define TIME_OUT 86400
#define PORT 53
#define PACKET_BUF_SIZE 4096 // 512字节（RFC1035规定），这个大小可以在互联网上畅通无阻，不会因为路径中某MTU（通常≥576（RFC791））太小而导致分片。

typedef struct DNSHEADER    //DNS报文报头字段
{
	unsigned short ID;      //2 bytes
	unsigned short Flag;    //2 bytes
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
	unsigned short QDCount; //2 bytes
	unsigned short ANCount; //2 bytes
	unsigned short NSCount; //2 bytes
	unsigned short ARCount; //2 bytes
} dnsHeader;

typedef struct DNSQUERY
{
	char* Qname;            //查询域名
	unsigned short Qtype;   //2 bytes
	/*
	A(1) : IPv4
	AAAA(28) : IPv6
	*/
	unsigned short Qclass;  //IN(1), 2 bytes
} dnsQuery;

typedef struct DNSRR
{
	char* Name;             //restore Domain Name
	unsigned short Type;    //16 bits
	unsigned short Class;   //16 bits
	unsigned int TTL;       //32 bits
	unsigned short RDLength;//16 bits
	unsigned char* RData;            //restore IP address
} dnsRR;

typedef struct DNSPacket
{
	dnsHeader header;
	dnsQuery question;
	dnsRR answer;
	dnsRR authority;
	dnsRR additional;
} dnsPacket;

typedef struct idRecord
{
	unsigned short ServerID;				//发送给Server的报文ID号
	unsigned short ClientID;				//发送给Client的报文ID号
	struct sockaddr_in sa;				//用户的socket address
	time_t timestamp;					//时间戳
} IDRecord;

IDRecord IPTable[RECORD_SIZE];			//ID转换表
unsigned short curID;					//当前取的ID号

int lookUpTxt(char* DN, unsigned char* IP)
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

        if( strcmp( DN, domainName ) == 0)         
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
					IP[i] = (unsigned char)atoi(transform);
					i++;
					transform = temp + 1;
				}
				temp++;
			}
			IP[i] = (unsigned char)atoi(transform);
			flag = 1;
        }
    }
	return flag;
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

void recvPacket(int* bufLen, int sockfd, char* buf, int packetSize, struct sockaddr_in* sockFrom, socklen_t* sockLen)
{
    *bufLen = recvfrom(sockfd, (char*) buf, packetSize, 0, (struct sockaddr *) sockFrom, sockLen);
}

// 打印以字节形式显示的报文
void printPacket (const char* preface, struct sockaddr_in *sockFrom, char *buf, int bufLen)
{
    printf("%s %s:%d (%d bytes)\n", preface, inet_ntoa (sockFrom->sin_addr), ntohs (sockFrom->sin_port), bufLen);
    uint8_t *buf_8 = (uint8_t *) buf;
    printf("Raw bytes:\n");
    for (int i = 0; i < bufLen; i++) printf ("%02x ", buf_8[i]);
    printf("\n");
}

// 获取报文中的name类字段
void getName(char **name, uint8_t* startPoint, uint8_t** endPoint){
    uint8_t *nameGap = startPoint;
    int nameLen = 0;  
    int namePartNum = 0;
    while (*nameGap)
    {
        namePartNum ++;
        nameLen += *nameGap + 1;
        *nameGap = '\0';
        nameGap = startPoint + nameLen;
    }
    *endPoint = nameGap + 1;

    *name = malloc(nameLen * sizeof(char));
    *name[0] = '\0';
    char* namePart = (char*) (startPoint+1);
    for (int i = 0; i < namePartNum; i++)
    {
        strcat(*name, namePart);
        namePart += strlen(namePart) + 1;
        if (i != namePartNum - 1) strcat(*name, ".");
    }
}

void Decode(dnsPacket* Packet, struct sockaddr_in *sockFrom, char *buf, int bufLen)
{
    // Header部分
    uint16_t *buf_16 = (uint16_t *) buf;
    uint8_t *buf_8 = (uint8_t *) buf;
    // enum ...
    Packet->header.ID = ntohs (buf_16[0]);
    Packet->header.Flag = ntohs (buf_16[1]);
    Packet->header.QDCount = ntohs (buf_16[2]);
    Packet->header.ANCount = ntohs (buf_16[3]);
    Packet->header.NSCount = ntohs (buf_16[4]);
    Packet->header.ARCount = ntohs (buf_16[5]);

    // Question部分
    uint16_t *buf_16_QnameEnd = NULL;
    getName(&Packet->question.Qname, &buf_8[12], (uint8_t**) &buf_16_QnameEnd);
    Packet->question.Qtype = ntohs(buf_16_QnameEnd[0]);
    Packet->question.Qclass = ntohs(buf_16_QnameEnd[1]);

    // // Answer部分
    // uint16_t *buf_16_lastEnd = buf_16_QnameEnd + 2;
    // for (int i = 0; i < Packet->header.ANCount; i++)
    // {
    //     uint16_t *buf_16_answer = buf_16_lastEnd;
    //     Packet->answer.Name = Packet->question.Qname; // ??
    //     Packet->answer.Type = ntohs(buf_16_answer[1]);
    //     Packet->answer.Class = ntohs(buf_16_answer[2]);
    //     uint32_t *buf_TTL = (uint32_t *) &buf_16_answer[3];
    //     Packet->answer.TTL = ntohl(buf_TTL[0]);
    //     Packet->answer.RDLength = ntohs(buf_16_answer[5]);
    //     // Packet->answer.RData = ;

    //     break;
    //     // buf_16_lastEnd = 
    // }
}

// 打印以结构体形式显示的报文
void printPacketS(const char* preface, dnsPacket* Packet, struct sockaddr_in *sockFrom, int bufLen)
{
    printf ("%s %s:%d (%d bytes)\n", preface, inet_ntoa (sockFrom->sin_addr), ntohs (sockFrom->sin_port), bufLen);

    printf("Struct:\n");

    printf("  Header:\n");
    printf ("\tID %04x,\n"
            "\tFALG %04x,\n"
            "\tQDCOUNT %04x,\n"
            "\tANCOUNT %04x,\n"
            "\tNSCOUNT %04x,\n"
            "\tARCOUNT %04x,\n",
            Packet->header.ID,
            Packet->header.Flag,
            Packet->header.QDCount,
            Packet->header.ANCount,
            Packet->header.NSCount,
            Packet->header.ARCount
    );
    printf("\n");

    printf("  Qustion:\n");
    printf ("\tQName %s,\n"
            "\tQType %04x,\n"
            "\tQClass %04x,\n",
            Packet->question.Qname,
            Packet->question.Qtype,
            Packet->question.Qclass
    );
    printf("\n");

    for (int i = 0; i < Packet->header.ANCount; i++)
    {
        printf("  Answer %d:\n", i);
        printf ("\tName %s,\n"
                "\tType %04x,\n"
                "\tClass %04x,\n"
                "\tTTL %08x,\n"
                "\tRDLength %04x,\n",  
                Packet->answer.Name,
                Packet->answer.Type,
                Packet->answer.Class,
                Packet->answer.TTL,
                Packet->answer.RDLength
        );
        printf("\tRData");
        for (int i = 0; i < 4; i++)
        {
            printf(" %d",Packet->answer.RData[i]);
        }
        printf(",\n");
        printf("\n");
    }
    
    
}

void Encode(dnsPacket* Packet, char *buf, int *bufLen)
{
    char* curBuf = buf;
    uint16_t numTrans = 0;
    uint32_t numTransL = 0;

    // Header部分
    numTrans = htons(Packet->header.ID);
    memcpy(curBuf, &numTrans, sizeof(uint16_t));
    curBuf += sizeof(uint16_t);
    numTrans = htons(Packet->header.Flag);
    memcpy(curBuf, &numTrans, sizeof(uint16_t));
    curBuf += sizeof(uint16_t);
    numTrans = htons(Packet->header.QDCount);
    memcpy(curBuf, &numTrans, sizeof(uint16_t));
    curBuf += sizeof(uint16_t);
    numTrans = htons(Packet->header.ANCount);
    memcpy(curBuf, &numTrans, sizeof(uint16_t));
    curBuf += sizeof(uint16_t);
    numTrans = htons(Packet->header.NSCount);
    memcpy(curBuf, &numTrans, sizeof(uint16_t));
    curBuf += sizeof(uint16_t);
    numTrans = htons(Packet->header.ARCount);
    memcpy(curBuf, &numTrans, sizeof(uint16_t));
    curBuf += sizeof(uint16_t);

	
    // Question部分
    for (int i = 0; i < Packet->header.QDCount; i++)
    {
        int len = strlen(Packet->question.Qname);
        char Qname[len + 2];
        // char Qname[200];
        char* curPartPos = Qname;
        int lastLen = 0;
        for (int i = 0; i < strlen(Packet->question.Qname) + 1; i++)
        {
            if (Packet->question.Qname[i] == '.' || Packet->question.Qname[i] == '\0')
            {
                curPartPos[0] = i - lastLen;
                curPartPos++;
                strncpy(curPartPos, &Packet->question.Qname[lastLen], i - lastLen);
                curPartPos += i - lastLen;
                lastLen = i + 1;
            }
        }
        Qname[strlen(Packet->question.Qname)+1] = '\0'; //可能有问题
        
        memcpy(curBuf, Qname, sizeof(Qname));
        curBuf += sizeof(Qname);
        numTrans = htons(Packet->question.Qtype);
        memcpy(curBuf, &numTrans, sizeof(uint16_t));
        curBuf += sizeof(uint16_t);
        numTrans = htons(Packet->question.Qtype);
        memcpy(curBuf, &numTrans, sizeof(uint16_t));
        curBuf += sizeof(uint16_t);
        
        break;
    }

    // Answer部分
    for (int i = 0; i < Packet->header.ANCount; i++)
    {   
        numTrans = htons(0xc00c);
        memcpy(curBuf, &numTrans, sizeof(uint16_t));
        curBuf += sizeof(uint16_t);
        numTrans = htons(Packet->answer.Type);
        memcpy(curBuf, &numTrans, sizeof(uint16_t));
        curBuf += sizeof(uint16_t);
        numTrans = htons(Packet->answer.Class);
        memcpy(curBuf, &numTrans, sizeof(uint16_t));
        curBuf += sizeof(uint16_t);
        numTransL = htonl(Packet->answer.TTL);
        memcpy(curBuf, &numTransL, sizeof(uint32_t));
        curBuf += sizeof(uint32_t);
        numTrans = htons(Packet->answer.RDLength);
        memcpy(curBuf, &numTrans, sizeof(uint16_t));
        curBuf += sizeof(uint16_t);

        uint32_t IPSum = 0;
        for (int i = 0; i < 4; i++)
        {
            IPSum = IPSum * 256 + Packet->answer.RData[i];
        }
        numTransL = htonl(IPSum);
        memcpy(curBuf, &numTransL, sizeof(uint32_t));
        curBuf += sizeof(uint32_t);
        break;
        // buf_16_lastEnd = 
    }

    *bufLen = curBuf - buf;
}

void sendPacket(int sockfd, char* buf, int packetSize, struct sockaddr_in* sockTo, socklen_t* sockLen)
{
    sendto(sockfd, buf, packetSize, 0 ,(struct sockaddr*) sockTo, *sockLen);
}

void work(int sockfd)
{
    // 因特网服务端通信对象
    struct sockaddr_in sockINServer;
    // 客户端网络通信对象
    struct sockaddr_in sockFrom;
    socklen_t sockLen = sizeof(struct sockaddr_in);

    // 接收
    char recvBuf[PACKET_BUF_SIZE];
    int recvBufLen;
    recvPacket(&recvBufLen, sockfd, recvBuf, PACKET_BUF_SIZE, &sockFrom, &sockLen);
    printPacket("Recv from", &sockFrom, recvBuf, recvBufLen);

	time_t curTime;				//当前时间
	time(&curTime);

    dnsPacket packetFrom;
    dnsPacket packetSend;
	// 解码
	Decode(&packetFrom, &sockFrom, recvBuf, recvBufLen);
    printPacketS("Recv from", &packetFrom, &sockFrom, recvBufLen);

	if ((packetFrom.header.Flag & 0x8000) == 0)
	{
		char* DN;
		unsigned char IP[4];
		DN = packetFrom.question.Qname;
		if (lookUpTxt(DN, IP) && (packetFrom.question.Qtype == 1) && (packetFrom.question.Qclass == 1))						//若在表中
		{
			if (IP[0] == (unsigned char)0 && IP[1] == (unsigned char)0 && IP[2] == (unsigned char)0 && IP[3] == (unsigned char)0)		//若IP为0.0.0.0
			{
				packetSend.header.ID = packetFrom.header.ID;
				packetSend.header.Flag = 0x8583;				//QR=1响应报，OPCODE=0标准查询，AA=1，D=1，RA=1允许递归，ROCODE=3指定域名不存在
				packetSend.header.ANCount = 1;
                packetSend.header.QDCount = 1;
                packetSend.header.ARCount = 0;
                packetSend.header.NSCount = 0;
				packetSend.question.Qname = packetFrom.question.Qname;
				packetSend.question.Qtype = packetFrom.question.Qtype;
				packetSend.question.Qclass = packetFrom.question.Qclass;
				packetSend.answer.Name = DN;
				packetSend.answer.Type = 1;						//类型为A地址
				packetSend.answer.Class = 1;					//Internet数据
				packetSend.answer.TTL = TIME_OUT;					//生存时间
				packetSend.answer.RDLength = 4;					//资源数据的字节数为4个字节
				packetSend.answer.RData = IP;
			}
			else         //若IP不为0.0.0.0
			{
				packetSend.header.ID = packetFrom.header.ID;
				packetSend.header.Flag = 0x8580;				//QR=1响应报，OPCODE=0标准查询，RD=1，RA=1允许递归，ROCODE=3指定域名不存在
				packetSend.header.ANCount = 1;
				packetSend.header.QDCount = 1;
				packetSend.header.ARCount = 0;
				packetSend.header.NSCount = 0;
				packetSend.question.Qname = packetFrom.question.Qname;
				packetSend.question.Qtype = packetFrom.question.Qtype;
				packetSend.question.Qclass = packetFrom.question.Qclass;
				packetSend.answer.Name = DN;
				packetSend.answer.Type = 1;						//类型为A地址
				packetSend.answer.Class = 1;					//Internet数据
				packetSend.answer.TTL = TIME_OUT;					//生存时间
				packetSend.answer.RDLength = 4;					//资源数据的字节数为4个字节
				packetSend.answer.RData = IP;
			}
			// 编码 & 发送
            char sendBuf[PACKET_BUF_SIZE];
            int sendBufLen = 0;
            Encode(&packetSend, sendBuf, &sendBufLen);
            printPacketS("Send to", &packetSend, &sockFrom, sendBufLen);
            printPacket("Send to", &sockFrom, sendBuf, sendBufLen);
            sendPacket(sockfd, sendBuf, sendBufLen, &sockFrom, &sockLen);
		}
		else     //若不在表中，需要上传给Internet DNS服务器
		{
			int i = 0;
			while (1)
			{
				if (IPTable[i].timestamp && curTime - IPTable[i].timestamp > TIME_OUT)		//寻找ID对应表中的空表项，并清空超时表项
					IPTable[i].timestamp = 0;
				if (!IPTable[i].timestamp)			//找到空表项
					break;
				i++;
			}
			IPTable[i].ClientID = packetFrom.header.ID;			//配置ID对应表				
			IPTable[i].ServerID = curID++;						
			memcpy(&(IPTable[i].sa), &sockFrom, sizeof(struct sockaddr_in));
			IPTable[i].timestamp = curTime;

			memcpy(&packetSend, &packetFrom, sizeof(packetFrom));		//将接收的结构体复制给即将发送的结构体
			packetSend.header.ID = IPTable[i].ServerID;					//头部ID改为服务器ID
			//发给Internet DNS服务器
			//编码发送
			// 编码 & 发送
            char sendBuf[PACKET_BUF_SIZE];
            int sendBufLen = 0;
            Encode(&packetSend, sendBuf, &sendBufLen);
            printPacketS("Send to", &packetSend, &sockINServer, sendBufLen);
            printPacket("Send to", &sockINServer, sendBuf, sendBufLen);
			sendPacket(sockfd, sendBuf, sendBufLen, &sockINServer, &sockLen);		//发送给服务器
		}
	}
	//已知数据包来自Internet Server的情况
	else if ((packetFrom.header.Flag & 0x8000) == 1)
	{
		int i = 0;
		while ((curTime - IPTable[i].timestamp > TIME_OUT) || (IPTable[i].ServerID != packetFrom.header.ID))	//寻找对应的服务器ID，从而通过ID对应表找到对应的客户端
		{
			//找下一个对应表项
			i++;

			//没找到
			if (i >= RECORD_SIZE) return;
		}

		IPTable[i].timestamp = 0;
		memcpy(&packetSend, &packetFrom, sizeof(packetFrom));		//将接收的结构体复制给即将发送的结构体
		packetSend.header.ID = IPTable[i].ClientID;					//头部ID改为服务器ID
		//服务器端ID转换成客户端的报文ID
		//发给客户端
		//编码发送
        char sendBuf[PACKET_BUF_SIZE];
        int sendBufLen = 0;
        Encode(&packetSend, sendBuf, &sendBufLen);
        printPacketS("Send to", &packetSend, &sockFrom, sendBufLen);
        printPacket("Send to", &sockFrom, sendBuf, sendBufLen);
		sendPacket(sockfd, sendBuf, sendBufLen, &IPTable[i].sa, &sockLen);			//发送给ID对应表中和用户对应的socket address
	}
    /*// 编码 & 发送
    char sendBuf[PACKET_BUF_SIZE];
    // Encode(&packetSend, sendBuf);
    Encode(&packetFrom, sendBuf);
    // int sendBufLen = strlen(sendBuf) * sizeof(char);
    // sendBufLen需要修改
    sendPacket(sockfd, sendBuf, sizeof(dnsPacket), &sockFrom, &sockLen);*/
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
	curID = (unsigned short)time(0);

    while(1){
        work(sockfd);
    }
    
    // close(sockfd);
    return 0;
}