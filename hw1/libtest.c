#include <unistd.h>
#include <fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <unistd.h>
//#include "test.h"

int main(){
    FILE*fp_get=fopen("./config.txt","r");
    
    char keyword[10][100];
    
    char*line_get=NULL;
    size_t len_get=0;
    int flag=0;
    int index=0;
    while(getline(&line_get,&len_get,fp_get)!=-1){
        
        //if(line_get=="") continue;
        printf("line:%s\n",line_get);
        char temp[1024]="";
        strncpy(temp,line_get,strlen(line_get)-2);
        printf("temp:%s\n",temp);
        //printf("strlen: %d line : %s----\n",strlen(temp),temp);
        if(strncmp(temp,"BEGIN getaddrinfo-blacklist",27)==0&&strlen(temp)==27){
            printf("match\n");
            flag=flag+1;
        }
        else if(strncmp(temp,"END getaddrinfo-blacklist",23)==0&&strlen(temp)==23){
            printf("len temp:%d\n",strlen(temp));
            printf("break\n");
            break;
        }else if(flag){
            //keyword[flag-1]=temp;
            memset(keyword[flag-1],0,strlen(temp)+1);
            memcpy(keyword[flag-1],temp,strlen(temp));
            printf("index:%d %s\n",flag-1,keyword[flag-1]);
            flag=flag+1;
        }
        
    }
    fclose(fp_get);
    //open("")
    int fp_create;
    fp_create=open("./open_test.txt",O_RDWR);
    //printf("ok\n");
        //printf("exit filename:%s,fp_create:%d",filename,fp_create);
        for(int i=0;i<flag-1;i++){
            off_t offset=lseek(fp_create,-strlen(keyword[i]),SEEK_END);
            char*check_buf;
            int check_len=read(fp_create,check_buf,1024);
            if(check_len<strlen(keyword[i])) continue;
            if(strstr(check_buf,keyword[i])!=NULL){
                //errno=EIO;
                printf("block\n");
                //dprintf(log,"[logger] read (%d,%p,%ld) = -1\n",fd,&buf,count);
                
            }
        }
        close(fp_create);
    return 0;
}