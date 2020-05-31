//
//  dnsBOServer.c
//  CTest
//
//  Created by NI on 2018/6/17.
//  Copyright © 2018年 NI. All rights reserved.
//

//微软.商业 & 学习.组织 TLD & 2LD
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define SERVER_PORT 53
#define BUFER_SIZE 1024

unsigned short length = 0;
unsigned short query_domain_length = 0;
int pos = 0;

/**
 * Tag Types
 */
enum tag_type {
    standard_query_NRD = 0x0000, //standard query with no-recursive
    standard_query_RD = 0x0100, //standard query with recursive
    inverse_query_NRD = 0x0800, //inverse query with no-recursive
    inverse_query_RD = 0x0900, //inverse query with recursive
    standard_res_NAA_NRA = 0x8000, //standard response with not-authoritive and not-recursive
    standard_res_AA_NRA = 0x8400,  //standard response with authoritive and not-recursive
    name_wrong_res = 0x8003, //don't have such domian name
    format_wrong_res = 0x8001 //the format is wrong
} tag;
/**
 * Resource Record Types
 */
enum RR_type {
    A = 0x0001,
    CNAME = 0x0005,
    MX = 0x000F
};
/**
 * Resource Record class
 */
enum RR_class {
    IN = 0x0001,
};

struct dns_header{
    uint16_t id;
    uint16_t tag;
    uint16_t queryNum;
    uint16_t answerNum;
    uint16_t authorityNum;
    uint16_t additionNum;
};

struct dns_query{
    char *name;
    uint16_t qType;
    uint16_t qClass;
};
struct dns_rr{
    char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_len;
    char *Data;
};

struct dns_MX_rr{
    char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_len;
    uint16_t Preference;
    char *exchange;
};
struct dns_packet{
    struct dns_header *header;
    struct dns_query *question;
    struct dns_rr *answer;
    struct dns_rr *authority;
    struct dns_rr *additional;
};
struct dns_MX_packet{
    struct dns_header *header;
    struct dns_query *question;
    struct dns_MX_rr *answer;
    struct dns_rr *authority;
    struct dns_rr *additional;
};

//方法大全
void initializeQueryPacket(struct dns_packet *qPacket);
void initializeAnswerPacket(struct dns_packet *aPacket);
void initializeAnswerMXPacket(struct dns_MX_packet *aPacket);

void setMXPacket(struct dns_MX_packet *packet, char *buffer);
void getMXPacket(struct dns_MX_packet *packet, char *buffer);
void setPacket(struct dns_packet *packet, char *buffer);
void getPacket(struct dns_packet *packet, char *buffer);

void setHeader(struct dns_header *header, char *buffer);
void getHeader(struct dns_header *header, char *buffer);

void setQuestion(struct dns_query *question, char *buffer);
void getQuestion(struct dns_query *question, char *buffer);

void setMXAnswer(struct dns_MX_rr *answer, char *buffer);
void setAnswer(struct dns_rr *answer, char *buffer);
void setAuthority(struct dns_rr *authority, char *buffer);
void setAdditional(struct dns_rr *additional, char *buffer);

void setrrdata(char* data, char *buffer);
char *getrrdata(char *buffer);

void put2byte(uint16_t value, char *buffer);
uint16_t get2byte(char *buffer);

void put4byte(uint32_t value, char *buffer);
uint32_t get4byte(char *buffer);

void set_A(char *ip, struct dns_rr *type, struct dns_packet packet);
void set_CNAME(char *cname, struct dns_rr *type, struct dns_packet packet);
void set_MX(char *domain, int level, struct dns_MX_rr *data, struct dns_packet packet);
void get_A(struct dns_rr *type, char *buffer);
void get_CNAME(struct dns_rr *type, char *buffer);
void get_MX(struct dns_MX_rr *type, char *buffer);

//char *cutDomainName(char* domain_name, int times);
void setDomain(char *name, char *buffer);
void setIp(char *ip, char *buffer);
char *getIp(char *buffer);
char *getDomainshow(char* buffer);
char *getDomain(char* buffer);
char *getDomaincopscreen(char* domain);
char *cutDomain(char *domain, int level);
int cutDomainNum(char *domain);

int checkFile(char *name, uint16_t type);
int getPFile(char *name, uint16_t type, struct dns_rr *rr);
int getMXPFile(char *name, uint16_t type, struct dns_MX_rr *rr);

uint16_t getType(char *type);
uint16_t getClass(char *class);

int changeDN(char *DN,char *name);

void printName(int len, char *name);

int HtoD(uint8_t num);

void printPacket(struct dns_packet packet);
void printMXPacket(struct dns_MX_packet packet);








//主程序
int main(int argc, char *argv[]){
    
    char *udp_sendbuf = (char*)malloc(sizeof(char) *BUFER_SIZE);
    memset(udp_sendbuf, '\0' , BUFER_SIZE);
    char *udp_recbuf = (char*)malloc(sizeof(char) * BUFER_SIZE);
    memset(udp_recbuf, '\0' , BUFER_SIZE);
    
    char name[BUFER_SIZE];
    int udp_sock;
    int alllen = 0;
    int iDataNum;
    struct sockaddr_in serverAddr;
    struct sockaddr_in clientAddr;
    struct sockaddr_in rootAddr;
    struct sockaddr_in nextAddr;
    int client;
    int clientlen = sizeof(clientAddr);
    
    //创建一个socket 协议， 类型udp/tcp， default 0
    if((udp_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0){
        printf("socket() failed.\n");
        exit(1);
    }
    
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.3.3.2");
    //    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(SERVER_PORT);
    
    if((bind(udp_sock, (struct sockaddr *) &serverAddr, sizeof(serverAddr))) < 0){
        printf("bind() failed.\n");
        exit(1);
    }
    
    
    printf("Port : %d\n", serverAddr.sin_port);
    printf("Server address : %s\n", inet_ntoa(serverAddr.sin_addr));
    printf("Wating for data on Port UDP: %d\n", SERVER_PORT);
    
    while(1){
        
        if((iDataNum = recvfrom(udp_sock, udp_recbuf, BUFER_SIZE, 0, (struct sockaddr *) &clientAddr, &clientlen)) < 0){
            printf("Something wrong with socket receving\n");
        }
        printf("received a packet from %s\n", inet_ntoa(clientAddr.sin_addr));
        
        //初始化查询包
        struct dns_packet query_packet;
        pos = 0;
        length = 0;
        initializeQueryPacket(&query_packet);
        getPacket(&query_packet, udp_recbuf);
        printPacket(query_packet);
        
        //查询数据库是否存在
        if(checkFile(query_packet.question->name, query_packet.question->qType) == 2){
            //不存在，告诉下一个服务器
            if (query_packet.question->qType == 1 || query_packet.question->qType == 5) {
                printf("***In A and CNAME***");
                struct dns_packet answer_packet;
                initializeAnswerPacket(&answer_packet);
                answer_packet.header = query_packet.header;
                answer_packet.question = query_packet.question;
                answer_packet.header->answerNum = 1;
                answer_packet.header->tag = standard_res_NAA_NRA;
                getPFile(query_packet.question->name, answer_packet.question->qType, answer_packet.answer);
                printPacket(answer_packet);
                
                memset(udp_sendbuf, '\0', BUFER_SIZE);
                pos = 0;
                length = 0;
                setPacket(&answer_packet, udp_sendbuf);
                printf("Send len: %d\n", length);
                
            }
            else if(query_packet.question->qType == 15){
                printf("\n***In MX Cache***\n");
                printf("\n***2222222***\n");
                struct dns_MX_packet answer_MX_packet;
                initializeAnswerMXPacket(&answer_MX_packet);
                answer_MX_packet.header = query_packet.header;
                answer_MX_packet.question = query_packet.question;
                answer_MX_packet.header->tag = standard_res_NAA_NRA;
                answer_MX_packet.header->answerNum = 1;
                getMXPFile(query_packet.question->name, MX, answer_MX_packet.answer);
                answer_MX_packet.header->additionNum = 1;
                getPFile(answer_MX_packet.answer->exchange, A, answer_MX_packet.additional);
                printMXPacket(answer_MX_packet);
                
                memset(udp_sendbuf, '\0', BUFER_SIZE);
                pos = 0;
                length = 0;
                setMXPacket(&answer_MX_packet, udp_sendbuf);
                printf("Send len: %d\n", length);
                
            }
            
        }
        else if(checkFile(query_packet.question->name, query_packet.question->qType) == 0 || checkFile(query_packet.question->name, query_packet.question->qType) == 1){
            
            printf("***In NO***");
            struct dns_packet answer_packet;
            initializeAnswerPacket(&answer_packet);
            answer_packet.header = query_packet.header;
            answer_packet.question = query_packet.question;
//            answer_packet.header->authorityNum = 1;
            answer_packet.header->tag = name_wrong_res;
//            char *servername = "商业&组织";
//            changeDN(servername, name);
//            answer_packet.authority->name = name;
//            answer_packet.authority->type = A;
//            answer_packet.authority->class = 0x0001;
//            answer_packet.authority->ttl = 8600;
//            answer_packet.authority->data_len = strlen("127.3.3.2");
//            answer_packet.authority->Data = "127.3.3.2";
            printPacket(answer_packet);
            
            memset(udp_sendbuf, '\0', BUFER_SIZE);
            pos = 0;
            length = 0;
            setPacket(&answer_packet, udp_sendbuf);
            printf("Send len: %d\n", length);
            
        }
        
        if((sendto(udp_sock, udp_sendbuf, length, 0, (struct sockaddr *) &clientAddr, sizeof(clientAddr))) == -1){
            printf("Something wrong with socket sending packet\n");
            exit(1);
        }
    }
    return 0;
}



//********************************
void initializeQueryPacket(struct dns_packet *qPacket){
    qPacket->header = (struct dns_header *)malloc(sizeof(struct dns_header));
    memset(qPacket->header, 0, sizeof(struct dns_header));
    
    qPacket->question = (struct dns_query *)malloc(sizeof(struct dns_query));
    qPacket->question->name = (char *)malloc(sizeof(char) * BUFER_SIZE);
    memset(qPacket->question, 0, sizeof(struct dns_query));
    //memset(qPacket->question->name, 0, BUFER_SIZE);
    
    qPacket->answer = NULL;
    qPacket->authority = NULL;
    qPacket->additional = NULL;
    
}
void initializeAnswerPacket(struct dns_packet *aPacket){
    aPacket->header = (struct dns_header *)malloc(sizeof(struct dns_header));
    memset(aPacket->header, 0, sizeof(struct dns_header));
    
    aPacket->question = (struct dns_query *)malloc(sizeof(struct dns_query));
    aPacket->question->name = (char *)malloc(sizeof(char) * BUFER_SIZE);
    memset(aPacket->question, 0, sizeof(struct dns_query));
    //    memset(aPacket->question->name, 0, BUFER_SIZE);
    
    aPacket->answer = (struct dns_rr *)malloc(sizeof(struct dns_rr));
    aPacket->answer->name = (char *)malloc(sizeof(char) * BUFER_SIZE);
    aPacket->answer->Data = (char *)malloc(sizeof(char) * BUFER_SIZE);
    memset(aPacket->answer, 0, sizeof(struct dns_rr));
    //    memset(aPacket->answer->name, 0, BUFER_SIZE);
    //    memset(aPacket->answer->Data, 0, BUFER_SIZE);
    
    aPacket->authority = (struct dns_rr *)malloc(sizeof(struct dns_rr));
    aPacket->authority->name = (char *)malloc(sizeof(char) * BUFER_SIZE);
    aPacket->authority->Data = (char *)malloc(sizeof(char) * BUFER_SIZE);
    memset(aPacket->authority, 0, sizeof(struct dns_rr));
    //    memset(aPacket->authority->name, 0, BUFER_SIZE);
    //    memset(aPacket->authority->Data, 0, BUFER_SIZE);
    
    aPacket->additional = (struct dns_rr *)malloc(sizeof(struct dns_rr));
    aPacket->additional->name = (char *)malloc(sizeof(char) * BUFER_SIZE);
    aPacket->additional->Data = (char *)malloc(sizeof(char) * BUFER_SIZE);
    memset(aPacket->additional, 0, sizeof(struct dns_rr));
    //    memset(aPacket->additional->name, 0, BUFER_SIZE);
    //    memset(aPacket->additional->Data, 0, BUFER_SIZE);
}
void initializeAnswerMXPacket(struct dns_MX_packet *aPacket){
    aPacket->header = (struct dns_header *)malloc(sizeof(struct dns_header));
    memset(aPacket->header, 0, sizeof(struct dns_header));
    
    aPacket->question = (struct dns_query *)malloc(sizeof(struct dns_query));
    aPacket->question->name = (char *)malloc(sizeof(char) * BUFER_SIZE);
    memset(aPacket->question, 0, sizeof(struct dns_query));
    //    memset(aPacket->question->name, 0, BUFER_SIZE);
    
    aPacket->answer = (struct dns_MX_rr *)malloc(sizeof(struct dns_MX_rr));
    aPacket->answer->name = (char *)malloc(sizeof(char) * BUFER_SIZE);
    aPacket->answer->exchange = (char *)malloc(sizeof(char) *BUFER_SIZE);
    memset(aPacket->answer, 0, sizeof(struct dns_MX_rr));
    //        memset(aPacket->answer->name, 0, BUFER_SIZE);
    //        memset(aPacket->answer->Data, 0, BUFER_SIZE);
    
    aPacket->authority = (struct dns_rr *)malloc(sizeof(struct dns_rr));
    aPacket->authority->name = (char *)malloc(sizeof(char) * BUFER_SIZE);
    aPacket->authority->Data = (char *)malloc(sizeof(char) * BUFER_SIZE);
    memset(aPacket->authority, 0, sizeof(struct dns_rr));
    //    memset(aPacket->authority->name, 0, BUFER_SIZE);
    //    memset(aPacket->authority->Data, 0, BUFER_SIZE);
    
    aPacket->additional = (struct dns_rr *)malloc(sizeof(struct dns_rr));
    aPacket->additional->name = (char *)malloc(sizeof(char) * BUFER_SIZE);
    aPacket->additional->Data = (char *)malloc(sizeof(char) * BUFER_SIZE);
    memset(aPacket->additional, 0, sizeof(struct dns_rr));
    //    memset(aPacket->additional->name, 0, BUFER_SIZE);
    //    memset(aPacket->additional->Data, 0, BUFER_SIZE);
}

//********************************
void setMXPacket(struct dns_MX_packet *packet, char *buffer){
    setHeader(packet->header, buffer);
    printf("buffer11: %x\n",buffer[1]);
    setQuestion(packet->question, buffer);
    if(packet->header->answerNum != 0){
        setMXAnswer(packet->answer, buffer);
    }
    if(packet->header->authorityNum != 0){
        setAuthority(packet->authority, buffer);
    }
    if(packet->header->additionNum != 0){
        setAdditional(packet->additional, buffer);
    }
}
void getMXPacket(struct dns_MX_packet *packet, char *buffer){
    getHeader(packet->header, buffer);
    getQuestion(packet->question, buffer);
    printf("\nAfter header, question\n");
    if (packet->header->answerNum != 0) {
        get_MX(packet->answer, buffer);
    } else {
        packet->answer = NULL;
    }
    if (packet->header->authorityNum != 0) {
        get_A(packet->additional, buffer);
    } else {
        packet->authority = NULL;
    }
    if (packet->header->additionNum != 0) {
        get_A(packet->additional, buffer);
    } else {
        packet->additional = NULL;
    }
}
void setPacket(struct dns_packet *packet, char *buffer){
    setHeader(packet->header, buffer);
    printf("buffer11: %x\n",buffer[1]);
    setQuestion(packet->question, buffer);
    if(packet->header->answerNum != 0){
        setAnswer(packet->answer, buffer);
    }
    if(packet->header->authorityNum != 0){
        setAuthority(packet->authority, buffer);
    }
    if(packet->header->additionNum != 0){
        setAdditional(packet->additional, buffer);
    }
    
}
void getPacket(struct dns_packet *packet, char *buffer){
    getHeader(packet->header, buffer);
    getQuestion(packet->question, buffer);
    printf("\nAfter header, question\n");
    if (packet->header->answerNum != 0) {
        if(packet->question->qType == 1){
            printf("in getanswer\n");
            get_A(packet->answer, buffer);
        }
        else if(packet->question->qType == 5){
            get_CNAME(packet->answer, buffer);
        }
    } else {
        packet->answer = NULL;
    }
    if (packet->header->authorityNum != 0) {
        if(packet->question->qType == 1){
            get_A(packet->authority, buffer);
        }
        else if(packet->question->qType == 5){
            get_CNAME(packet->authority, buffer);
        }
    } else {
        packet->authority = NULL;
    }
    if (packet->header->additionNum != 0) {
        if(packet->question->qType == 1){
            get_A(packet->additional, buffer);
        }
        else if(packet->question->qType == 5){
            get_CNAME(packet->additional, buffer);
        }
    } else {
        packet->additional = NULL;
    }
}

//********************************
void setHeader(struct dns_header *header, char *buffer){
    put2byte(header->id, buffer);
    put2byte(header->tag, buffer);
    put2byte(header->queryNum, buffer);
    put2byte(header->answerNum, buffer);
    put2byte(header->authorityNum, buffer);
    put2byte(header->additionNum, buffer);
}
void getHeader(struct dns_header *header, char *buffer){
    printf("pos: %d\n",pos);
    header->id = get2byte(buffer);
    printf("pos: %d\n",pos);
    header->tag = get2byte(buffer);
    printf("pos: %d\n",pos);
    header->queryNum = get2byte(buffer);
    printf("pos: %d\n",pos);
    header->answerNum = get2byte(buffer);
    printf("pos: %d\n",pos);
    header->authorityNum = get2byte(buffer);
    printf("pos: %d\n",pos);
    header->additionNum = get2byte(buffer);
    printf("pos: %d\n",pos);
}

//********************************
void setQuestion(struct dns_query *question, char *buffer){
    setDomain(question->name, buffer);
    put2byte(question->qType, buffer);
    put2byte(question->qClass, buffer);
}
void getQuestion(struct dns_query *question, char *buffer){
    printf("\nin getquestion\n");
    printf("pos: %d\n",pos);
    char *temp = getDomain(buffer);
    int temp_len = strlen(temp);
    printf("\ntemp len: %d\n",temp_len);
    pos = pos + temp_len + 1;
    question->name = temp;
    printf("\npos: %d\n",pos);
    question->qType = get2byte(buffer);
    printf("pos: %d\n",pos);
    question->qClass = get2byte(buffer);
    printf("\nqClass: %d\n",question->qClass);
    printf("pos: %d\n",pos);
    
}

//********************************
void setAnswer(struct dns_rr *answer, char *buffer){
    printf("\nanswer name:%s\n",answer->name);
    setDomain(answer->name, buffer);
    put2byte(answer->type, buffer);
    put2byte(answer->class, buffer);
    put4byte(answer->ttl, buffer);
    put2byte(answer->data_len, buffer);
    if(answer->type == 1){
        setIp(answer->Data, buffer);
    }
    else if(answer->type == 5){
        setrrdata(answer->Data, buffer);
    }
}
void setMXAnswer(struct dns_MX_rr *answer, char *buffer){
    setDomain(answer->name, buffer);
    put2byte(answer->type, buffer);
    put2byte(answer->class, buffer);
    put4byte(answer->ttl, buffer);
    put2byte(answer->data_len, buffer);
    put2byte(answer->Preference, buffer);
    setrrdata(answer->exchange, buffer);
}

//********************************
void setAuthority(struct dns_rr *authority, char *buffer){
    printf("\naaaa:%s\n",authority->name);
    setDomain(authority->name, buffer);
    put2byte(authority->type, buffer);
    put2byte(authority->class, buffer);
    put4byte(authority->ttl, buffer);
    put2byte(authority->data_len, buffer);
    if(authority->type == 1){
        setIp(authority->Data, buffer);
    }
    else if(authority->type == 5){
        setrrdata(authority->Data, buffer);
    }
    else if(authority->type == 15){
        setIp(authority->Data, buffer);
    }
}

//********************************
void setAdditional(struct dns_rr *additional, char *buffer){
    printf("\naaaaol:%s\n",additional->name);
    setDomain(additional->name, buffer);
    put2byte(additional->type, buffer);
    put2byte(additional->class, buffer);
    put4byte(additional->ttl, buffer);
    put2byte(additional->data_len, buffer);
    if(additional->type == 1){
        setIp(additional->Data, buffer);
    }
    else if(additional->type == 5){
        setrrdata(additional->Data, buffer);
    }
    else if(additional->type == 15){
        setIp(additional->Data, buffer);
    }
}

//********************************
void setrrdata(char* data, char *buffer){
    int len = strlen(data) + 1;
    printf("\nstrlen:%d\n", len);
    strcat(buffer+length,data);
    pos = len + length;
    length+=len;
}
char *getrrdata(char *buffer){
    int se = pos;
    int temp = -1;
    int j;
    char *pareseDomain = (char*)malloc(sizeof(char) *BUFER_SIZE);
    memset(pareseDomain, '\0' , BUFER_SIZE);
    //    printf("buff: %d\n",buffer[12]);
    //    printf("buff: %d\n",buffer[16]);
    //    printf("buff: %d\n",buffer[22]);
    while(buffer[se] != 0) {
        int len = (int)buffer[se];
        for(j = 0 ; j<len+1 ; j++){
            temp++;
            pareseDomain[temp] = buffer[se+j];
            printf("\npd: %d, %d", temp, pareseDomain[temp]);
        }
        se = se + len+1;
    }
    //    printf("\npd: %s", pareseDomain);
    //    printf("%c",pareseDomain[10]);
    //    printf("\n%d\n",strlen(pareseDomain));
    printf("\npareseDomain: %d,%d,%d", temp,pareseDomain[temp],strlen(pareseDomain));
    temp++;
    pareseDomain[temp] = 0;
    printf("\npareseDomain: %d,%d,%d", temp,pareseDomain[temp],strlen(pareseDomain));
    return pareseDomain;
}

//********************************
void put2byte(uint16_t value, char *buffer){
    char right,left;
    right = value&0XFF;//低八位
    left = value>>8;//高八位
    buffer[pos] = left;
    buffer[pos+1] = right;
    //    printf("pos: %d left: %x ",pos,buffer[pos]);
    //    printf("right: %x\n",buffer[pos+1]);
    length+=2;
    pos+=2;
}
uint16_t get2byte(char *buffer){
    //    printf("\npos: %d", pos);
    uint16_t value = buffer[pos]<<8 | buffer[pos+1];
    //    printf("\nvalue: %x",value);
    pos+=2;
    return value;
}

//********************************
void put4byte(uint32_t value, char *buffer){
    //    char right,left;
    //    right = value&0XFF;//低8位
    //    left = value>>8;//高8位
    uint16_t right, left;
    uint8_t l_l, l_r, r_l, r_r;
    left = (uint16_t)(value>>16);
    right = (uint16_t)value;
    l_r = left&0XFF;
    l_l = left>>8;
    r_r = right&0XFF;
    r_l = right>>8;
    buffer[pos] = l_l;
    buffer[pos+1] = l_r;
    buffer[pos+2] = r_l;
    buffer[pos+3] = r_r;
    length+=4;
    pos+=4;
}
uint32_t get4byte(char *buffer){
    //    uint16_t left = buffer[pos]<<8 | buffer[pos+1];
    //    uint16_t right = buffer[pos+2]<<8 | buffer[pos+3];
    //    uint32_t value = left<<16 | right;
    uint32_t temp = 0xff & (uint32_t)buffer[pos+3];
    uint32_t value = (uint32_t)buffer[pos]<<24 | (uint32_t)buffer[pos+1]<<16 | (uint32_t)buffer[pos+2]<<8 | temp;
    pos+=4;
    return value;
}

//********************************记录
void set_A(char *ip, struct dns_rr *type, struct dns_packet packet){
    
    printf("\nin A\n");
    int datalen = sizeof(ip);
    type->name = packet.question->name;
    type->type = A;
    type->class = packet.question->qClass;
    type->ttl = 0x1212;
    type->data_len = datalen;
    type->Data = ip;
    
}
void set_CNAME(char *cname, struct dns_rr *type, struct dns_packet packet){
    
    char *domain = (char*)malloc(sizeof(char) *BUFER_SIZE);
    memset(domain, '\0' , BUFER_SIZE);
    int l = changeDN(cname, domain);
    printName(l, domain);
    int datalen = strlen(domain);
    type->name = packet.question->name;
    type->type = CNAME;
    type->class = packet.question->qClass;
    type->ttl = 0x1212;
    type->data_len = datalen;
    type->Data = domain;
    
}
void set_MX(char *domain, int level, struct dns_MX_rr *data, struct dns_packet packet){
    char *aim = (char*)malloc(sizeof(char) *BUFER_SIZE);
    memset(aim, '\0' , BUFER_SIZE);
    int l = changeDN(domain, aim);
    printName(l, aim);
    int datalen = l + 2;
    printf("\ndata len:%d**********************\n ", l);
    data->name = packet.question->name;
    data->type = MX;
    data->class = packet.question->qClass;
    data->ttl = 0x1212;
    data->data_len = datalen;
    data->Preference = level;
    data->exchange = aim;
}
void get_A(struct dns_rr *type, char *buffer){
    printf("in get_A\n");
    char *temp = getDomain(buffer);
    int temp_len = strlen(temp);
    pos = pos + temp_len + 1;
    type->name = temp;
    type->type = get2byte(buffer);
    type->class = get2byte(buffer);
    type->ttl = get4byte(buffer);
    type->data_len = get2byte(buffer);
    type->Data = getIp(buffer);
}
void get_CNAME(struct dns_rr *type, char *buffer){
    char *temp = getDomain(buffer);
    int temp_len = strlen(temp);
    pos = pos + temp_len + 1;
    type->name = temp;
    type->type = get2byte(buffer);
    type->class = get2byte(buffer);
    type->ttl = get4byte(buffer);
    type->data_len = get2byte(buffer);
    char *temp_cdata = getrrdata(buffer);
    int temp_cdata_len = strlen(temp_cdata);
    pos = pos + temp_cdata_len + 1;
    type->Data = temp_cdata;
}
void get_MX(struct dns_MX_rr *data, char *buffer){
    char *temp = getDomain(buffer);
    int temp_len = strlen(temp);
    pos = pos + temp_len + 1;
    data->name = temp;
    data->type = get2byte(buffer);
    data->class = get2byte(buffer);
    data->ttl = get4byte(buffer);
    data->data_len = get2byte(buffer);
    data->Preference = get2byte(buffer);
    char *temp_cdata = getrrdata(buffer);
    int temp_cdata_len = strlen(temp_cdata);
    pos = pos + temp_cdata_len + 1;
    data->exchange = temp_cdata;
}

//********************************
void setDomain(char *name, char *buffer){
    printf("\ndomain name:%s\n",name);
    int len = strlen(name) + 1;
    printf("\nDomain strlen:%d\n", len);
    strcat(buffer+length,name);
    pos = len + length;
    length+=len;
}

void setIp(char *ip, char *buffer){
    uint32_t t = inet_addr (ip);
    uint16_t right, left;
    uint8_t l_l, l_r, r_l, r_r;
    left = (uint16_t)(t>>16);
    right = (uint16_t)t;
    l_l = left>>8;
    l_r = left&0XFF;
    r_l = right>>8;
    r_r = right&0XFF;
    buffer[pos] = r_r;
    buffer[pos+1] = r_l;
    buffer[pos+2] = l_r;
    buffer[pos+3] = l_l;
    length+=4;
    pos+=4;
}
char *getIp(char *buffer){
    uint32_t iph = get4byte(buffer);
    uint16_t right, left;
    uint8_t l_l, l_r, r_l, r_r;
    left = (uint16_t)(iph>>16);
    right = (uint16_t)iph;
    l_l = left>>8;
    l_r = left&0XFF;
    r_l = right>>8;
    r_r = right&0XFF;
    
    printf("rr:%d ",r_r);
    printf("rl:%d ", r_l);
    printf("lr:%d ", l_r);
    printf("ll:%x ", l_l);
    
    int a,b,c,d;
    a = HtoD(r_r);
    b = HtoD(r_l);
    c = HtoD(l_r);
    d = HtoD(l_l);
    printf("a:%d ", a);
    printf("b:%d ", b);
    printf("c:%d ", c);
    printf("d:%d ", d);
    
    
    char ti0[4];
    char ti1[4];
    char ti2[4];
    char ti3[4];
    
    sprintf(ti0,"%d",d);
    sprintf(ti1,"%d",c);
    sprintf(ti2,"%d",b);
    sprintf(ti3,"%d",a);
    char result[65535];
    memset(&result, 0, 65535);
    //    printf("ipipipipipipipi:%c",ti0);
    //    strcat(result,temp_ip);
    strcat(result,ti0);
    strcat(result,".");
    strcat(result,ti1);
    strcat(result,".");
    strcat(result,ti2);
    strcat(result,".");
    strcat(result,ti3);
    printf("*****t*****:%s",result);
    return result;
    
}
char* getDomainshow(char* buffer){
    int se = 12;
    int judget = 0;
    int temp = -1;
    int i, j;
    char *pareseDomain = (char*)malloc(sizeof(char) *BUFER_SIZE);
    memset(pareseDomain, '\0' , BUFER_SIZE);
    //    printf("buff: %d\n",buffer[12]);
    //    printf("buff: %d\n",buffer[16]);
    //    printf("buff: %d\n",buffer[22]);
    while(buffer[se] != 0) {
        int len = (int)buffer[se];
        //        printf("\nbuff: %d\n",buffer[se]);
        if(judget == 0){
            for(i = 1 ; i<len+1 ; i++){
                //                printf("88old%d",temp);
                temp++;
                pareseDomain[temp] = buffer[se+i];
                //                printf("88new%d",temp);
                //                printf("%c\n",pareseDomain[temp]);
            }
        }
        else{
            for(j = 0 ; j<len+1 ; j++){
                if(j == 0){
                    temp++;
                    pareseDomain[temp] = '.';
                    // printf(".\n");
                    //                    printf("99%d",temp);
                    //                   printf("%c\n",pareseDomain[temp]);
                }
                else{
                    temp++;
                    pareseDomain[temp] = buffer[se+j];
                    //                   printf("00%d",temp);
                    //                   printf("%c\n",pareseDomain[temp]);
                }
            }
        }
        se = se + len+1;
        judget++;
    }
    pareseDomain[temp+1] = '\0';
    //    printf("\npd: %s", pareseDomain);
    //    printf("%c",pareseDomain[10]);
    //    printf("\n%d\n",strlen(pareseDomain));
    return pareseDomain;
}
char* getDomain(char* buffer){
    int se = pos;
    int temp = -1;
    int j;
    char *pareseDomain = (char*)malloc(sizeof(char) *BUFER_SIZE);
    memset(pareseDomain, '\0' , BUFER_SIZE);
    //    printf("buff: %d\n",buffer[12]);
    //    printf("buff: %d\n",buffer[16]);
    //    printf("buff: %d\n",buffer[22]);
    while(buffer[se] != 0) {
        int len = (int)buffer[se];
        for(j = 0 ; j<len+1 ; j++){
            temp++;
            pareseDomain[temp] = buffer[se+j];
            printf("\npd: %d, %d", temp, pareseDomain[temp]);
        }
        se = se + len+1;
    }
    //    printf("\npd: %s", pareseDomain);
    //    printf("%c",pareseDomain[10]);
    //    printf("\n%d\n",strlen(pareseDomain));
    printf("\npareseDomain: %d,%d,%d", temp,pareseDomain[temp],strlen(pareseDomain));
    temp++;
    pareseDomain[temp] = 0;
    printf("\npareseDomain: %d,%d,%d", temp,pareseDomain[temp],strlen(pareseDomain));
    return pareseDomain;
}
char *getDomaincopscreen(char* domain){
    int judget = 0;
    int temp = -1;
    int i, j;
    char *pareseDomain = (char*)malloc(sizeof(char) *BUFER_SIZE);
    memset(pareseDomain, '\0' , BUFER_SIZE);
    //    printf("buff: %d\n",buffer[12]);
    //    printf("buff: %d\n",buffer[16]);
    //    printf("buff: %d\n",buffer[22]);
    while(domain[judget] != 0) {
        int len = (int)domain[judget];
        //        printf("\nbuff: %d\n",domain[judget]);
        if(judget == 0){
            for(i = 1 ; i<len+1 ; i++){
                temp++;
                pareseDomain[temp] = domain[judget+i];
                //                printf("a new %d ",temp);
                //                printf("%c\n",pareseDomain[temp]);
            }
        }
        else{
            for(j = 0 ; j<len+1 ; j++){
                if(j == 0){
                    temp++;
                    pareseDomain[temp] = '.';
                    //                     printf(".\n");
                    //                     printf("b %d ",temp);
                    //                     printf("%c\n",pareseDomain[temp]);
                }
                else{
                    temp++;
                    pareseDomain[temp] = domain[judget+j];
                    //                    printf("c %d ",temp);
                    //                    printf("%c\n",pareseDomain[temp]);
                }
            }
        }
        judget = judget + len+1;
    }
    pareseDomain[temp+1] = '\0';
    //    printf("\npd: %s", pareseDomain);
    //    printf("%c",pareseDomain[10]);
    //    printf("\n%d\n",strlen(pareseDomain));
    return pareseDomain;
}
char *cutDomain(char *domain, int level){
    char *result = (char*)malloc(BUFER_SIZE);
    char test_str[BUFER_SIZE] = {0};
    char *ptr,*retptr;
    int i=0;
    strcpy(test_str, domain);
    ptr = test_str;
    int total = 0;
    
    while ((retptr=strtok(ptr, ".")) != NULL) {
        ptr = NULL;
        total++;
    }
    i=0;
    strcpy(test_str, domain);
    ptr = test_str;
    retptr = NULL;
    printf("total: %d\n", total);
    while ((retptr=strtok(ptr, ".")) != NULL) {
        i++;
        ptr = NULL;
        if(i>(total-level)){
            strcat(result, retptr);
            if(i!= total){
                strcat(result, ".");
            }
        }
    }
    return result;
}
int cutDomainNum(char *domain){
    char *result = (char*)malloc(BUFER_SIZE);
    char test_str[BUFER_SIZE] = {0};
    char *ptr,*retptr;
    int i=0;
    strcpy(test_str, domain);
    ptr = test_str;
    int total = 0;
    
    while ((retptr=strtok(ptr, ".")) != NULL) {
        ptr = NULL;
        total++;
    }
    return total;
}

//********************************
int changeDN(char *DN,char *name)
{
    int i = strlen(DN) - 1; //13
    int j = i + 1; //14
    int k;
    name[j+1] = 0; //15
    for(k = 0; i >= 0; i--,j--) {
        if(DN[i] == '.') {
            name[j] = k;
            k = 0;
        }
        else {
            name[j] = DN[i];
            k++;
        }
    }
    name[0] = k;
    return (strlen(DN) + 2);
}

//********************************
void printName(int len, char *name)
{
    int i;
    for(i = 0; i < len; i++) printf("%x.",name[i]);
    printf("\n");
}

//char* cutDomainName(char* domain_name, int times) {
//}

uint16_t getType(char *type) {
    enum RR_type type_code;
    if (strcmp(type, "A") == 0) {
        type_code = A;
        return type_code;
    }
    else if (strcmp(type, "MX") == 0)
    {
        type_code = MX;
        return type_code;
    } else if (strcmp(type, "CNAME") == 0) {
        type_code = CNAME;
        return type_code;
    } else {
        printf("No such query type, [A | MX | CNAME] is considered\n");
        exit(0);
    }
}
uint16_t getClass(char *class) {
    enum RR_class class_code;
    if (strcmp(class, "IN") == 0) {
        class_code = IN;
        return class_code;
    }
    else {
        printf("No such query class, [IN] is considered\n");
        exit(0);
    }
}

int HtoD(uint8_t num){
    int a = 0;
    //    if((num & 256) != 0){
    //        a = a + 256;
    //    }
    if((num & 128) != 0){
        a = a + 128;
    }
    if((num & 64) != 0){
        a = a + 64;
    }
    if((num & 32) != 0){
        a = a + 32;
    }
    if((num & 16) != 0){
        a = a + 16;
    }
    if((num & 8) != 0){
        a = a + 8;
    }
    if((num & 4) != 0){
        a = a + 4;
    }
    if((num & 2) != 0){
        a = a + 2;
    }
    if((num & 1) != 0){
        a = a + 1;
    }
    return a;
}

int checkFile(char *name, uint16_t type){
    char *nname = getDomaincopscreen(name);
    int judge = 0;
    char fname[BUFER_SIZE];
    char ftype[BUFER_SIZE];
    char fclass[BUFER_SIZE];
    //    char fttl[BUFER_SIZE];
    int fttl;
    char frdata[BUFER_SIZE];
    FILE *fp;
    fp = fopen("tldboconfig.txt", "r");//假定存在这个文件中。
    if(fp == NULL)
    {
        printf("ERROR!\n");
        return -1;
    }

    if(cutDomainNum(nname)<=2){
        judge = 1;
    }
    else{
        while(~fscanf(fp,"%s%s%s%d%s", fname, ftype, fclass, &fttl, frdata)){
            if(strcmp(fname, cutDomain(nname,3)) == 0 && getType(ftype) == type){
                printf("In check\n");
                printf("fname:%s\n",fname);
                printf("ftype:%s\n",ftype);
                printf("fclass:%s\n",fclass);
                printf("fttl:%d\n",fttl);
                printf("frdata:%s\n",frdata);
                judge = 2;
                break;//找到一个就退出。 如果要多个，可以自行优化。
            }
        }
    }

//    if(judge == 0){
//        while(~fscanf(fp,"%s%s%s%d%s", fname, ftype, fclass, &fttl, frdata)){
//            if(strcmp(fname, cutDomain(nname,2)) == 0 && getType(ftype) == type){
//                printf("In check\n");
//                printf("fname:%s\n",fname);
//                printf("ftype:%s\n",ftype);
//                printf("fclass:%s\n",fclass);
//                printf("fttl:%d\n",fttl);
//                printf("frdata:%s\n",frdata);
//                judge = 1;
//                break;//找到一个就退出。 如果要多个，可以自行优化。
//            }
//        }
//    }
    fclose(fp);
    return judge;
}
int getPFile(char *name, uint16_t type, struct dns_rr *rr){
    char *nname = getDomaincopscreen(name);
    int judge = 0;
    
    char fname[BUFER_SIZE];
    char ftype[BUFER_SIZE];
    char fclass[BUFER_SIZE];
    char *commandata = (char *)malloc(BUFER_SIZE);
    memset(commandata, 0, BUFER_SIZE);
    //    char fttl[BUFER_SIZE];
    int fttl;
    char frdata[BUFER_SIZE];
    int datalen = 0;
    FILE *fp;
    fp = fopen("tldboconfig.txt", "r");//假定存在这个文件中。
    if(fp == NULL)
    {
        printf("ERROR!\n");
        return -1;
    }
    while(~fscanf(fp,"%s%s%s%d%s", fname, ftype, fclass, &fttl, frdata)){
        //根据不同服务器改变筛选条件
        if(strcmp(fname, cutDomain(nname,3)) == 0 && getType(ftype) == type){
            printf("\n***OK Find***\n");
            printf("\nIn get\n");
            printf("fname:%s %d\n",fname, strlen(fname));
            printf("ftype:%s\n",ftype);
            printf("fclass:%s\n",fclass);
            printf("fttl:%d\n",fttl);
            printf("frdata:%s\n",frdata);
            
            judge = 2;
            printf("xxxxxxx");
            rr->name = name;
            rr->type = getType(ftype);
            rr->class = getClass(fclass);
            rr->ttl = fttl;
            printf("xxxxxxx");
            if(getType(ftype) == A){
                printf("aaaaaaaa");
                rr->data_len = sizeof(inet_addr(frdata));
                rr->Data = frdata;
            }
            else if(getType(ftype) == CNAME){
                printf("cccccccc");
                changeDN(frdata, commandata);
                rr->data_len = strlen(commandata)+1;
                rr->Data = commandata;
            }
            printf("eeeeeeeee");
            break;//找到一个就退出。 如果要多个，可以自行优化。
        }
    }
    if(judge == 0){
        while(~fscanf(fp,"%s%s%s%d%s", fname, ftype, fclass, &fttl, frdata)){
            //根据不同服务器改变筛选条件
            if(strcmp(fname, cutDomain(nname,2)) == 0){
                printf("\n***OK Find***\n");
                printf("\nIn get\n");
                printf("fname:%s %d\n",fname, strlen(fname));
                printf("ftype:%s\n",ftype);
                printf("fclass:%s\n",fclass);
                printf("fttl:%d\n",fttl);
                printf("frdata:%s\n",frdata);
                
                judge = 1;
                printf("xxxxxxx");
                rr->name = name;
                rr->type = getType(ftype);
                rr->class = getClass(fclass);
                rr->ttl = fttl;
                printf("xxxxxxx");
                if(getType(ftype) == A){
                    printf("aaaaaaaa");
                    rr->data_len = sizeof(inet_addr(frdata));
                    rr->Data = frdata;
                }
                else if(getType(ftype) == CNAME){
                    printf("cccccccc");
                    changeDN(frdata, commandata);
                    rr->data_len = strlen(commandata)+1;
                    rr->Data = commandata;
                }
                printf("eeeeeeeee");
                break;//找到一个就退出。 如果要多个，可以自行优化。
            }
        }
    }
    fclose(fp);
    return judge;
}
int getMXPFile(char *name, uint16_t type, struct dns_MX_rr *rr){
    char *nname = getDomaincopscreen(name);
    int judge = 0;
    char xname[BUFER_SIZE];
    char *xdata  = (char *)malloc(BUFER_SIZE);
    memset(xdata, 0, BUFER_SIZE);
    char fname[BUFER_SIZE];
    char ftype[BUFER_SIZE];
    char fclass[BUFER_SIZE];
    int fttl;
    char frdata[BUFER_SIZE];
    FILE *fp;
    fp = fopen("tldboconfig.txt", "r");//假定存在这个文件中。
    if(fp == NULL)
    {
        printf("ERROR!\n");
        return -1;
    }
    while(~fscanf(fp,"%s%s%s%d%s", fname, ftype, fclass, &fttl, frdata)){
        //根据不同服务器改变筛选条件
        if(strcmp(fname, cutDomain(nname,3)) == 0 && getType(ftype) == type){
            printf("\n***OK Find***\n");
            printf("\nMX In get\n");
            printf("fname:%s %d\n",fname, strlen(fname));
            printf("ftype:%s\n",ftype);
            printf("fclass:%s\n",fclass);
            printf("fttl:%d\n",fttl);
            printf("frdata:%s %d\n",frdata, strlen(frdata));
            judge = 2;
            
            printf("\nfrdata: %s\n",frdata);
            
            changeDN(frdata, xdata);
            
            rr->name = name;
            printf("in name: %s %lu\n",rr->name, strlen(rr->name));
            rr->type = getType(ftype);
            rr->class = getClass(fclass);
            rr->ttl = fttl;
            rr->data_len = (strlen(xdata) + 3);
            rr->Preference = 20;
            rr->exchange = xdata;
            printf("exchange: %s %lu\n",rr->exchange, strlen(rr->exchange));
            printf("CAONIMA");
            break;//找到一个就退出。 如果要多个，可以自行优化。
        }
    }
    if(judge == 0){
        while(~fscanf(fp,"%s%s%s%d%s", fname, ftype, fclass, &fttl, frdata)){
            //根据不同服务器改变筛选条件
            if(strcmp(fname, cutDomain(nname,2)) == 0){
                printf("\n***OK Find***\n");
                printf("\nMX In get\n");
                printf("fname:%s %d\n",fname, strlen(fname));
                printf("ftype:%s\n",ftype);
                printf("fclass:%s\n",fclass);
                printf("fttl:%d\n",fttl);
                printf("frdata:%s %d\n",frdata, strlen(frdata));
                judge = 1;
                
                printf("\nfrdata: %s\n",frdata);
                
                changeDN(frdata, xdata);
                
                rr->name = name;
                printf("in name: %s %lu\n",rr->name, strlen(rr->name));
                rr->type = getType(ftype);
                rr->class = getClass(fclass);
                rr->ttl = fttl;
                rr->data_len = (strlen(xdata) + 3);
                rr->Preference = 20;
                rr->exchange = xdata;
                printf("exchange: %s %lu\n",rr->exchange, strlen(rr->exchange));
                printf("CAONIMA");
                break;//找到一个就退出。 如果要多个，可以自行优化。
            }
        }
    }
    fclose(fp);
    return judge;
}

void printPacket(struct dns_packet packet){
    
    printf("\n********************************************\n");
    printf("Header:\n");
    printf("id: %d\n", packet.header->id);
    printf("tag: %d\n", packet.header->tag);
    printf("question number: %d\n", packet.header->queryNum);
    printf("answer number: %d\n", packet.header->answerNum);
    printf("authority number: %d\n", packet.header->authorityNum);
    printf("additional number: %d\n", packet.header->additionNum);
    printf("Question Section:\n");
    printf("name : %s\n", getDomaincopscreen(packet.question->name));
    printf("type : %d\n", packet.question->qType);
    printf("class : %d\n", packet.question->qClass);
    if (packet.header->answerNum == 1){
        printf("XXXXX\n");
        printf("Answer Section:\n");
        printf("name : %s\n", getDomaincopscreen(packet.answer->name));
        printf("type : %d\n", packet.answer->type);
        printf("class : %d\n", packet.answer->class);
        printf("ttl : %d\n", packet.answer->ttl);
        printf("data length : %d\n", packet.answer->data_len);
        if (packet.question->qType == 1) {
            printf("Address: %s", packet.answer->Data);
            printf("\n");
        }
        else if (packet.question->qType == 5) {
            printf("CNAME: %s\n", getDomaincopscreen(packet.answer->Data));
        }
    }
    if(packet.header->authorityNum != 0){
        printf("Autority Section:\n");
        printf("name: %s\n", getDomaincopscreen(packet.authority->name));
        printf("type: %d\n", packet.authority->type);
        printf("class: %d\n", packet.authority->class);
        printf("ttl: %d\n", packet.authority->ttl);
        printf("data length: %d\n", packet.authority->data_len);
        if (packet.authority->type == 1) {
            printf("Address: %s", packet.authority->Data);
            printf("\n");
        }
        else if (packet.authority->type == 5) {
            printf("CNAME: %s\n", getDomaincopscreen(packet.authority->Data));
        }
    }
    if(packet.header->additionNum != 0){
        printf("Addtional Section:\n");
        printf("name: %s\n", getDomaincopscreen(packet.additional->name));
        printf("type: %d\n", packet.additional->type);
        printf("class: %d\n", packet.additional->class);
        printf("ttl: %d\n", packet.additional->ttl);
        printf("data length: %d\n", packet.additional->data_len);
        if (packet.question->qType == 1) {
            printf("Address: %s", packet.additional->Data);
            printf("\n");
        }
        else if (packet.question->qType == 5) {
            printf("CNAME: %s\n", getDomaincopscreen(packet.additional->Data));
        }
    }
    printf("********************************************\n");
}
void printMXPacket(struct dns_MX_packet packet){
    
    printf("\n********************************************\n");
    printf("Header:\n");
    printf("id: %d\n", packet.header->id);
    printf("tag: %d\n", packet.header->tag);
    printf("question number: %d\n", packet.header->queryNum);
    printf("answer number: %d\n", packet.header->answerNum);
    printf("authority number: %d\n", packet.header->authorityNum);
    printf("additional number: %d\n", packet.header->additionNum);
    printf("Question Section:\n");
    printf("name : %s\n", getDomaincopscreen(packet.question->name));
    printf("type : %d\n", packet.question->qType);
    printf("class : %d\n", packet.question->qClass);
    if (packet.header->answerNum != 0){
        printf("Answer Section:\n");
        printf("name : %s\n",getDomaincopscreen(packet.answer->name));
        printf("type : %d\n", packet.answer->type);
        printf("class : %d\n", packet.answer->class);
        printf("ttl : %d\n", packet.answer->ttl);
        printf("data length : %d\n", packet.answer->data_len);
        printf("Preference: %d\n", packet.answer->Preference);
        printf("Mail Exchange: %s\n", getDomaincopscreen(packet.answer->exchange));
        printf("\n");
    }
    if(packet.header->authorityNum != 0){
        printf("Autority Section:\n");
        printf("name: %s\n", getDomaincopscreen(packet.authority->name));
        printf("type: %d\n", packet.authority->type);
        printf("class: %d\n", packet.authority->class);
        printf("ttl: %d\n", packet.authority->ttl);
        printf("data length: %d\n", packet.authority->data_len);
        if (packet.authority->type == 1) {
            printf("Address: %s", packet.authority->Data);
            printf("\n");
        }
        else if (packet.authority->type == 5) {
            printf("CNAME: %s\n", getDomaincopscreen(packet.authority->Data));
        }
    }
    if(packet.header->additionNum != 0){
        printf("Addtional Section:\n");
        printf("name: %s\n", getDomaincopscreen(packet.additional->name));
        printf("type: %d\n", packet.additional->type);
        printf("class: %d\n", packet.additional->class);
        printf("ttl: %d\n", packet.additional->ttl);
        printf("data length: %d\n", packet.additional->data_len);
        printf("Address: %s\n", packet.additional->Data);
    }
    printf("********************************************\n");
}
