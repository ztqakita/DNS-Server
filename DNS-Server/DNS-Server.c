#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int debugLevel = 0;//0�����޵�����Ϣ��1������������Ϣ��2�������ӵ�����Ϣ
char filename[100] = ".\dnsrelay.txt";
char dns_server_ip[20] = "192.168.0.1";

#define BUFFER_SIZE 1024
#define PORT 53

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
                    strcpy_s(filename, sizeof(filename), argv[count]);
                    flag = 1;
                    break;
                }
                i++;
            }
            if (flag == 0)
                strcpy_s(dns_server_ip, sizeof(dns_server_ip), argv[count]);
        }
    }
    printf("debuglevel:%d\n", debugLevel);
    printf("dns_server_ip:%s\n", dns_server_ip);
    printf("filename:%s\n", filename);
}

int main(int argc, char* argv[]) 
{
    initCommand(argc, argv);
    return 0;
}