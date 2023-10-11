#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include<sys/mman.h>
#include <fcntl.h>
#include<dlfcn.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ELF file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *filename = argv[1];
    printf("%s\n",filename);
    FILE *fp = fopen(filename, "rb");
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
    printf("elf\n");

    // 计算重定位表的地址和大小
    Elf64_Shdr *shdr_table = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr) * elf_header.e_shnum);
    if (!shdr_table) {
        fprintf(stderr, "Failed to allocate memory for section header table\n");
        exit(EXIT_FAILURE);
    }

    fseek(fp, elf_header.e_shoff, SEEK_SET);// section header start 
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
            printf(".rela.plt\n");
            rela_plt_hdr = &shdr_table[i];
            // break;
        }
        else if (shdr_table[i].sh_type == SHT_DYNSYM) {
            printf("dyn.sym\n");
            symtab_hdr = &shdr_table[i];
        }
        else if (shdr_table[i].sh_type == SHT_STRTAB && str_count==0) {
            printf("strtab\n");
            strtab_hdr = &shdr_table[i];
            str_count=1;
        }
        // printf("%d\n",i);
    }

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
    // for(int i=0;i<strtab_hdr->sh_size;i++){
    //     // if(!strncmp(&strtab[i],"open",4)){
    //         printf("%s %d\n",&strtab[i],i);

    // }
    // 在重定位表中查找 open 函数的符号
    long open_addr=0;
    for (int i = 0; i < num_relocations; i++) {
        Elf64_Rela *rela = &relocations[i];
        // printf("%d,%ld,%ld\n",i,ELF64_R_TYPE(rela->r_info),R_X86_64_JUMP_SLOT);
        if (ELF64_R_TYPE(rela->r_info) == R_X86_64_JUMP_SLOT) {
            Elf64_Sym *sym = &symbols[ELF64_R_SYM(rela->r_info)];
            char *symname = &strtab[sym->st_name];
            
            // printf("%s %lx st_name:%d\n",symname,rela->r_offset,sym->st_name);
            // printf("o")
            if (strncmp(symname, "read",4) == 0 && strlen(symname)==4) {
                printf("Found read at index %d, offset 0x%lx\n", i, rela->r_offset);
            }else if(strncmp(symname,"open",4)==0 && strlen(symname)==4){
                open_addr=rela->r_offset;
                printf("Found open at index %d, offset 0x%lx\n", i, rela->r_offset);
            }else if(strncmp(symname,"write",5)==0 && strlen(symname)==5){
                printf("Found write at index %d, offset 0x%lx\n", i, rela->r_offset);
            }
        }
    }

    fclose(fp);
    free(relocations);
    free(symbols);
    free(strtab);
    fp=fopen("/proc/self/maps","r");
    if(fp==-1){
        printf("can not open\n");
        //return -1;
    }
    //printf("ok\n");
    char*line=NULL;
    size_t len=0;
    long addr_array[5];
    int count=0;
    while(count<5&&getline(&line,&len,fp)!=-1){
		char*buf=strtok(line,"-");
		long number=strtol(buf,NULL,16);
		addr_array[count++]=number;
        printf("addr[%d]: %p\n",count-1,number);
        
	}
    fclose(fp);
    //printf("ok\n");
    if(mprotect(addr_array[3],addr_array[4]-addr_array[3],PROT_WRITE|PROT_READ)){
        perror("can not mprotect");
    }
    
    unsigned long *real_open_addr=(unsigned long*)(addr_array[0]+open_addr);
    printf("%p\n",real_open_addr);
    void*handle=dlopen("libtest.so",RTLD_LAZY);
    unsigned long* my_open=NULL;
    if(handle!=NULL) my_open=dlsym(handle,"open_t");
    *real_open_addr=my_open;
    dlclose(handle);

    return 0;
}