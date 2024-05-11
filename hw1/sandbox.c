#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include<sys/mman.h>
#include <fcntl.h>
#include<dlfcn.h>
#include<errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
int (*real_open)(const char *, int,mode_t);
ssize_t (*real_read)(int , void *, size_t );
ssize_t (*real_write)(int , const void* , size_t );
int (*real_connect)(int , const struct sockaddr *, socklen_t );
int (*real_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
int (*real_system)(const char *);
char* call_list[]={"open","read","connect","getaddrinfo","system","write"};
unsigned long call_addr[6];//recode function relative address
char block_list[4][1024][1024]={0};
/*
open : 0
read : 1
connect : 2
getaddrinfo : 3
*/
void block_string(); 
int __libc_start_main(int *(main) (int, char * *, char * *), int argc, char * * argv, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)){
    // Load the real __libc_start_main
    //dlopen(libc.so.6) ---->  dlsym("_libc_start_main")
    void*handle=dlopen("libc.so.6",RTLD_LAZY);
    int (*real__libc_start_main)(int *(main) (int, char * *, char * *), int argc, char * * argv, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end));
    real__libc_start_main=dlsym(handle,"__libc_start_main");
    dlclose(handle);
    // Load the real functions we need to hijack
    // Hijack the entry point and perform the necessary initializations
    block_string();
    init_t();
    //先call真正的function存起來,再蓋掉got table的位置,使用時會呼叫到function_t進行監控後再決定是否呼叫真正的open

    // Call the real __libc_start_main
    return (*real__libc_start_main)(main, argc, argv, init, fini, rtld_fini, stack_end);
}
void block_string(){
    char* config_env=getenv("SANDBOX_CONFIG");
    FILE*fp=fopen(config_env,"r");
    char*buf=NULL;
    size_t len=0;
    
    int idx=-1,sub_idx=0;
    while(getline(&buf,&len,fp)!=-1){
        if(strstr(buf,"BEGIN")!=NULL && strstr(buf,"blacklist")!=NULL){
            idx++;
            sub_idx=0;
        }else if(strstr(buf,"END")!=NULL && strstr(buf,"blacklist")!=NULL){
            continue;
        }else{
            char temp[10240]="";
            strncpy(temp,buf,strlen(buf)-2);
            if(strlen(temp)==0) continue;
            memcpy(block_list[idx][sub_idx++],temp,strlen(temp));
        }
    }
    fclose(fp);
}
int open_t(const char *pathname, int flags,mode_t mode){
    char* LOGGER_FD=getenv("LOGGER_FD");
    long log=strtol(LOGGER_FD,NULL,10);
    char keyword[1024];
    if(realpath(pathname,keyword)==NULL){
        fprintf(stderr,"open_realpath_fail");
        exit(EXIT_FAILURE);
    }
    for(int i=0;i<1024;i++){
        if(block_list[0][i][0]=='\0'){
            break;
        }
        if(strstr(block_list[0][i],keyword)!=NULL){
            errno=EACCES;
            dprintf(log,"[logger] open (\"%s\",%d,%d) = -1 \n",pathname,flags,mode);
            return -1;
        }
    }
    
    int open_return=real_open(pathname,flags,mode);
    dprintf(log,"[logger] open (\"%s\",%d,%p) = %d\n",pathname,flags,mode,open_return);
    return open_return;
}
ssize_t read_t(int fd,void*buf,size_t count){
    char* LOGGER_FD=getenv("LOGGER_FD");
    long log=strtol(LOGGER_FD,NULL,10);
    
    pid_t pid=getpid();
    char filename[100];
    sprintf(filename,"%d-%d-read.log",pid,fd);
    char write_buf[100000];
    ssize_t r=real_read(fd,write_buf,count);
    //printf("filename:%s\n",filename);
    char prev_buf[100000]="";
    int prev_fd=-1;
    int prev=0;
    mode_t fileMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    if(access(filename,F_OK)==0){
        prev=1;
    }
    prev_fd=open(filename,O_RDWR|O_CREAT,fileMode);
    for(int i=0;i<1024;i++){
        if(block_list[1][i][0]=='\0'){
            break;
        }
        if(prev==1){
            lseek(prev_fd,-strlen(block_list[1][i]),SEEK_END);
            real_read(prev_fd,prev_buf,strlen(block_list[1][i])+1);
            char temp[100000]="";
            strcpy(temp,write_buf);
            strcat(prev_buf,temp);
            if(strstr(prev_buf,block_list[1][i])!=NULL){
                errno=EIO;
                dprintf(log,"[logger] read (%d,%p,%ld) = -1\n",fd,&buf,count);
                return -1;
            }
            memset(prev_buf,0,sizeof(prev_buf));
            lseek(prev_fd,0,SEEK_END);
        }else{
            if(strstr(write_buf,block_list[1][i])!=NULL){
                errno=EIO;
                dprintf(log,"[logger] read (%d,%p,%ld) = -1\n",fd,&buf,count);
                return -1;
            }
        }
    }
    real_write(prev_fd,write_buf,r);
    close(prev_fd);
    dprintf(log,"[logger] read (%d,%p,%ld) = %ld\n",fd,&buf,count,r);
    memcpy(buf,write_buf,r);
    return r;
}
ssize_t write_t(int fd, const void *buf, size_t count){
    //printf("pass write\n");
    pid_t pid=getpid();
    char filename[100];
    int fp_create;
    sprintf(filename,"%d-%d-write.log",pid,fd);
    mode_t fileMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    fp_create=open(filename,O_RDWR|O_CREAT,fileMode);
    if(fp_create==-1){
        fprintf(stderr,"fail create file (write)");
        exit(EXIT_FAILURE);
    }
    if(access(filename,F_OK)==0){
        off_t offset=lseek(fp_create,0,SEEK_END);
    }
    real_write(fp_create,buf,strlen(buf));
    close(fp_create);
    char* LOGGER_FD=getenv("LOGGER_FD");
    long log=strtol(LOGGER_FD,NULL,10);
    dprintf(log,"[logger] write (%d,%p,%ld) = %ld\n",fd,&buf,count,strlen(buf));
    return real_write(fd,buf,count);
}
int connect_t(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    char *ip_s=inet_ntoa(((struct sockaddr_in *)addr)->sin_addr);
    char ip[1000];
    strcpy(ip,ip_s);
    char* LOGGER_FD=getenv("LOGGER_FD");
    long log=strtol(LOGGER_FD,NULL,10);
    
    for(int i=0;i<1024;i++){
        if(block_list[2][i][0]=='\0'){
            break;
        }
        char temp[1024]="";
        strcpy(temp,block_list[2][i]);
        char *t=strtok(temp,":");
        struct hostent *host;
        struct in_addr **addr_list;
        host=gethostbyname(t); //將網域名轉換成IP
        if(host == NULL){
            printf("fail to gethost\n");
            return -1;
        }
        addr_list=(struct in_addr **)host->h_addr_list; //取得IP位址
        for (i = 0; addr_list[i] != NULL; i++) {
            if(strncmp(ip,inet_ntoa(*addr_list[i]),strlen(ip))==0){
                dprintf(log,"[logger] connect (%d,%s,%d) = -1\n",sockfd,ip,addrlen);
                errno=ECONNREFUSED;
                return -1;
            }
        }
    }

    dprintf(log,"[logger] connect (%d,%s,%d) = 0\n",sockfd,ip,addrlen);
    return real_connect(sockfd, addr,  addrlen);
}
int getaddrinfo_t(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res){
    int ret_getaddr=real_getaddrinfo(node,service,hints,res);
    char* LOGGER_FD=getenv("LOGGER_FD");
    long log=strtol(LOGGER_FD,NULL,10);
    
    for(int i=0;i<1024;i++){
        if(block_list[3][i][0]=='\0'){
            break;
        }
        //printf("node:%s block:%s\n",node,block_list[3][i]);
        if(strcmp(node,block_list[3][i])==0){
            dprintf(log,"[logger] getaddrinfo (%s,%s,%p,%p) = %d\n",node,service,hints,res,EAI_NONAME);
            errno=EAI_NONAME;
            return EAI_NONAME;
        }
    }
    dprintf(log,"[logger] getaddrinfo (%s,%s,%p,%p) = %d\n",node,service,hints,res,ret_getaddr);
    return ret_getaddr;
}

int system_t(const char *command){
    char* LOGGER_FD=getenv("LOGGER_FD");
    long log=strtol(LOGGER_FD,NULL,10);
    dprintf(log,"[logger] system (%s)\n",command);
    int ret=real_system(command);
    return ret;
}
void memory_hack(){
    FILE*fp_base=fopen("/proc/self/maps","r");
    if(fp_base==-1){
        printf("can not open\n");
        return ;
    }
    char*line=NULL;
    size_t len=0;
    unsigned long addr_array[5];
    int count=0;
    while(getline(&line,&len,fp_base)!=-1){
        //printf("%s\n",line);
		char*buf=strtok(line,"-");
		long number=strtol(buf,NULL,16);
		addr_array[count++]=number;
        if(count==5) break;
	}
    fclose(fp_base);
    if(mprotect(addr_array[3],addr_array[4]-addr_array[3],PROT_WRITE|PROT_READ)){
        perror("can not mprotect");
    }

    unsigned long base=addr_array[0];
    int size=sizeof(call_addr)/sizeof(call_addr[0]);
    for(int i=0;i<size;i++){
        if(call_addr[i]==0) continue;
        call_addr[i]=base+call_addr[i];
        void (*addr)();
        switch(i){
            case 0:
                real_open=open;
                addr=open_t;
                break;
            case 1:
                real_read=read;
                addr=read_t;
                //*(call_addr[i])=read_t;
                break;
            case 2:
                real_connect=connect;
                addr=connect_t;
                break;
            case 3:
                real_getaddrinfo=getaddrinfo;
                addr=getaddrinfo_t;
                break;
            case 4:
                real_system=system;
                addr=system_t;
                break;
            case 5:
                real_write=write;
                addr=write_t;
                break;
        }
        unsigned long* temp=call_addr[i];
        *temp=addr;
    }
}
int init_t() {
    char filename[100]="";
    if(realpath("/proc/self/exe",filename)==NULL){
        fprintf(stderr,"Failed exist");
        exit(EXIT_FAILURE);
    }
    FILE*fp=fopen(filename,"rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // 读取 ELF 文件头
    Elf64_Ehdr elf_header; //header
    if (fread(&elf_header, sizeof(Elf64_Ehdr), 1, fp) != 1) {
        fprintf(stderr, "Failed to read ELF header from file %s\n", filename);
        exit(EXIT_FAILURE);
    }
    //printf("elf\n");

    // 计算重定位表的地址和大小
    Elf64_Shdr *shdr_table = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr) * elf_header.e_shnum); //e_shnum = number of section
    if (!shdr_table) {
        fprintf(stderr, "Failed to allocate memory for section header table\n");
        exit(EXIT_FAILURE);
    }

    fseek(fp, elf_header.e_shoff, SEEK_SET);// e_shoff = section header table offset
    if (fread(shdr_table, sizeof(Elf64_Shdr), elf_header.e_shnum, fp) != elf_header.e_shnum) {
        fprintf(stderr, "Failed to read section header table from file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    Elf64_Shdr *rela_plt_hdr = NULL;
    Elf64_Shdr *symtab_hdr = NULL;
    Elf64_Shdr *strtab_hdr = NULL;

    // 找到 .rela.plt 节
    int str_count=0;
    for (int i = 0; i < elf_header.e_shnum; i++) {
        // printf("header %d \n",shdr_table[i].sh_type);
        if (shdr_table[i].sh_type == SHT_RELA ) {
            //printf(".rela.plt\n");
            rela_plt_hdr = &shdr_table[i];
            // break;
        }
        else if (shdr_table[i].sh_type == SHT_DYNSYM) {
            //printf("dyn.sym\n");
            symtab_hdr = &shdr_table[i];
        }
        else if (shdr_table[i].sh_type == SHT_STRTAB && str_count==0) {
            //printf("strtab\n");
            strtab_hdr = &shdr_table[i];
            str_count=1;
        }
        // printf("%d\n",i);
    }
    //printf("ok\n");
    if (!rela_plt_hdr) {
        fprintf(stderr, "Failed to find .rela.plt section in file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    if (!symtab_hdr) {
        fprintf(stderr, "Failed to find symbol table section in file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    if (!strtab_hdr) {
        fprintf(stderr, "Failed to find string table section in file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // 读取 .rela.plt 节中的内容
    fseek(fp, rela_plt_hdr->sh_offset, SEEK_SET);
    size_t num_relocations = rela_plt_hdr->sh_size / rela_plt_hdr->sh_entsize;
    Elf64_Rela *relocations = (Elf64_Rela *)malloc(sizeof(Elf64_Rela) * (num_relocations));
    if (!relocations) {
        fprintf(stderr, "Failed to allocate memory for relocations\n");
        exit(EXIT_FAILURE);
    }

    if (fread(relocations, rela_plt_hdr->sh_entsize, num_relocations, fp) != num_relocations) {
        fprintf(stderr, "Failed to read relocations from file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // 读取符号表和字符串表
    fseek(fp, symtab_hdr->sh_offset, SEEK_SET);
    size_t num_symbols = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
    Elf64_Sym *symbols = (Elf64_Sym *)malloc(sizeof(Elf64_Sym) * num_symbols);
    if (!symbols) {
        fprintf(stderr, "Failed to allocate memory for symbols\n");
        exit(EXIT_FAILURE);
    }

    if (fread(symbols, symtab_hdr->sh_entsize, num_symbols, fp) != num_symbols) {
        fprintf(stderr, "Failed to read symbols from file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    fseek(fp, strtab_hdr->sh_offset, SEEK_SET);
    char *strtab = (char *)malloc(strtab_hdr->sh_size);
    if (!strtab) {
        fprintf(stderr, "Failed to allocate memory for string table\n");
        exit(EXIT_FAILURE);
    }

    if (fread(strtab, 1, strtab_hdr->sh_size, fp) != strtab_hdr->sh_size) {
        fprintf(stderr, "Failed to read string table from file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < num_relocations; i++) {
        Elf64_Rela *rela = &relocations[i];
        // printf("%d,%ld,%ld\n",i,ELF64_R_TYPE(rela->r_info),R_X86_64_JUMP_SLOT);
        //R_X86_64_JUMP_SLOT，dynamic linker will modify the corresponding symbol reference to point to the address of the function in the shared library
        if (ELF64_R_TYPE(rela->r_info) == R_X86_64_JUMP_SLOT) { 
            //ELF64_R_SYM(rela->r_info) = the index of symbol table
            Elf64_Sym *sym = &symbols[ELF64_R_SYM(rela->r_info)];
            //st_name = the index of string table
            char *symname = &strtab[sym->st_name];
            for(int j=0;j<sizeof(call_list)/sizeof(call_list[0]);j++){
                if(strcmp(symname,call_list[j])==0){
                    call_addr[j]=rela->r_offset;
                }
            }
        }
    }
    fclose(fp);
    free(relocations);
    free(symbols);
    free(strtab);
    memory_hack();
    return 0;
}

