#include "receiver.h"
#include "sha256.h"

UChar Y[Max];//存储文件内容、作为sha256的输入

int sendSeed(unsigned char *seed,int s_len,int sock){
    char* data=(char*)seed;
    int len=s_len;
    int rc;
     do{
        rc=write(sock, data, len);
        if(rc<0){
            printf("errno while sending seed is %d\n",errno);
            exit(0);
        }else{
            data+=rc;
            len-=rc;
        }
    }while(len>0);
    return len;
}

int recvEncryptedData(unsigned char *dae,int d_len,int sock){
    int rc;
    int len=d_len;
    do{
        rc=read(sock, dae, len);
        if(rc<0){
            printf("errno while receiving encrypted data is %d\n",errno);
            exit(0);
        }else{
            dae+=rc;
            len-=rc;
        }
    }while(len>0);
    return 0;

}

int recvPKeyAndLen(unsigned char *b_f, int32_t *pk_len,int sock){
    int left1=sizeof(*pk_len);
    int left2=0;
    char *data=(char*)pk_len;
    int rc1;
    int rc2;
    do{
        rc1=read(sock, data, left1);
        if(rc1<0){
            printf("errno while receiving public key length is %d\n",errno);
            exit(0);
        }else{
            data+=rc1;
            left1-=rc1;
        }
    }while(left1>0);


    left2=ntohl(*pk_len);
    do{
        rc2=read(sock, b_f, left2);
        if(rc2<0){
            printf("errno while receiving public key is %d\n",errno);
            exit(0);
        }else{
            b_f+=rc2;
            left2-=rc2;
        }
    }while(left2>0);
    return 0;
}

int genSeed(unsigned char* ranstr){
    int i,flag;
    srand(time(NULL));
    for(i = 0; i < SEED_LEN-1; i ++)
    {
		flag = rand()%3;
		switch(flag)
		{
		case 0:
			*(ranstr+i) = rand()%26 + 'a';
			break;
		case 1:
			*(ranstr+i) = rand()%26 + 'A';
			break;
		case 2:
			*(ranstr+i) = rand()%10 + '0';
			break;
		}
    }
    return i;
}

int recvFile(unsigned char *data_after_encrypt,unsigned char *data_after_decrypt,AES_KEY *AESDecryptKey,int sock){
    unsigned long fsize=0;
    char fs[8];
    char p_fs[16];
    char d_fs[16];
    recvEncryptedData((unsigned char*)p_fs,sizeof(p_fs),sock);
    AES_decrypt((unsigned char*)p_fs, (unsigned char*)d_fs, AESDecryptKey);
    strncpy(fs,(const char*)d_fs,8);
    fsize=*((unsigned long*)fs);
    printf("File size:%lu\n",fsize);
    unsigned long times=((unsigned long)(fsize/16))+1;
    char fn[256];
    memset(fn,0,sizeof(fn));
    char e_fn[256];
    memset(e_fn,0,sizeof(e_fn));
    recvEncryptedData((unsigned char*)e_fn,sizeof(e_fn),sock);
    AES_decrypt((unsigned char*)e_fn, (unsigned char*)fn, AESDecryptKey);
    printf("File name:%s\n",fn);
    FILE *fp;
    if((fp=fopen((const char*)fn,"wb+"))==NULL){
        printf("File error!\nEnding the program!\n");
        exit(0);
    }
    printf("Writing file...\n");
    for(int i=0;i<times;i++){
        recvEncryptedData(data_after_encrypt,16,sock);
        AES_decrypt(data_after_encrypt, data_after_decrypt, AESDecryptKey);
        if(i!=times-1){
            fwrite(data_after_decrypt,16,1,fp);
        }else{
            fwrite(data_after_decrypt,fsize%16,1,fp);
        }
    }

    printf("接收sha256摘要...\n");
    //定义并初始化接收sha256摘要的数据结构
    char e_r_sha256[256];
    memset(e_r_sha256,0,sizeof(e_r_sha256));
    char r_sha256[256];
    memset(r_sha256,0,sizeof(r_sha256));
    //分4段接收、解密sha256摘要
    recvEncryptedData((unsigned char *)&e_r_sha256[0],16,sock);
    AES_decrypt((unsigned char *)e_r_sha256, (unsigned char *)r_sha256, AESDecryptKey);
    recvEncryptedData((unsigned char *)&e_r_sha256[16],16,sock);
    AES_decrypt((unsigned char *)&e_r_sha256[16], (unsigned char *)&r_sha256[16], AESDecryptKey);
    recvEncryptedData((unsigned char *)&e_r_sha256[32],16,sock);
    AES_decrypt((unsigned char *)&e_r_sha256[32], (unsigned char *)&r_sha256[32], AESDecryptKey);
    recvEncryptedData((unsigned char *)&e_r_sha256[48],16,sock);
    AES_decrypt((unsigned char *)&e_r_sha256[48], (unsigned char *)&r_sha256[48], AESDecryptKey);
    //打印接收到的sha256摘要
    printf("收到的sha256摘要:\n");
    printf("%s\n",r_sha256);

    printf("计算sha256摘要...\n");
    //定义并初始化计算sha256摘要的数据结构
    unsigned char sha256[256];
    unsigned char e_sha256[256];
    memset(sha256,0,sizeof(sha256));
    memset(e_sha256,0,sizeof(e_sha256));
    //文件指针置位、计算sha256摘要
    fseek(fp,0,SEEK_SET);
    fread((void *)Y,(size_t)fsize,1,fp);
    Message_Digest M_D = sha256Compress(Y);
    //输出接收到的sha256到数组sha256[]中    
    int i;
    for(i=0;i<8;i++){
        sprintf((char*)&sha256[8*i], "%8x",M_D.H[i]);
    }
    //打印计算出的sha256摘要
    printf("计算出的sha256:\n");
    printf("%s\n",(char *)sha256);

    printf("执行sha256校验...\n");
    //再次打印收到的sha256摘要
    printf("收到的sha256摘要:\n");
    printf("%s\n",r_sha256);
    if(strcmp((char *)sha256, (char *)r_sha256)==0){
        printf("校验通过，文件有效\n");
    }else{
        printf("校验失败，文件无效\n");
    }

    fclose(fp);
    printf("Completes!\n");
}
