#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
char msg[10000000];
int get(const char *host,const char *addr,char *msg){
	int sockfd;
	sockaddr_in serv_addr;
	hostent *server;
	char buffer[65536]="GET ";
	strcat(buffer,addr);
	strcat(buffer," HTTP/1.1\r\nHost: ");
	strcat(buffer,host);
	strcat(buffer,"\r\n\r\n");
	sockfd=socket(AF_INET,SOCK_STREAM,0);
	server=gethostbyname(host);
	serv_addr.sin_family=AF_INET;
	bcopy((char *)server->h_addr,(char *)&serv_addr.sin_addr.s_addr,server->h_length);
	serv_addr.sin_port=htons(80);
	connect(sockfd,(sockaddr *)&serv_addr,sizeof serv_addr);
	send(sockfd,buffer,strlen(buffer),0);
	recv(sockfd,buffer,65535,0);
	int code=atoi(strstr(buffer," "));
	if(code!=200)return 0;
	int len=atoi(strstr(buffer,"\r\nContent-Length")+17),tmp=0;
	msg[0]=0;
	while((tmp+=recv(sockfd,buffer,65535,0))<len)strcat(msg,buffer);
	strcat(msg,buffer);
	close(sockfd);
	return 1;
}
int main(){
	if(get("www.baidu.com","/",msg))printf("%s",msg);
	return 0;
}
