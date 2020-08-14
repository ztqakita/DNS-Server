#include <stdio.h>
#include <string.h>

int debugLevel = 0;//0代表无调试信息，1代表简介调试信息，2代表复杂调试信息
char filename[100] = ".\dnsrelay.txt";
char dns_server_ip[20] = "192.168.0.1";

void initCommand(int argc, char* argv[])
{
    int count = 1;
    for (count = 1; count < argc; ++count) {
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

int main(int argc, char* argv[]) {

    initCommand(argc, argv);
    return 0;
}