#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
int main(){
    char *path="/etc/ssl/certs/Amazon_Root_CA_1.pem";
    char temp[1000];
    char *exist;
    exist=realpath(path,temp);
    if(exist==NULL){
        fprintf(stderr,"fail\n");
        return -1;
    }
    printf("%s\n",temp);
    return 0;
}