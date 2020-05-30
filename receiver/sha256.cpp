#include"sha256.h"
#include <string.h>

//以下变量用于sha256算法的填充和分组运算
SHA256 sha256=SHA256();
Message_Digest M_D;
UInt32 W[Max/4];//整型
UInt32 M[16];   //存分组信息

//64个32比特字的常数（前64个素数的立方根小数前32位）
const UInt32 K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
//初始化杂凑值（前8个素数的平方根小数前32位）
void SHA256::INIT(){
    MD.H[0] = 0x6a09e667;
    MD.H[1] = 0xbb67ae85;
    MD.H[2] = 0x3c6ef372;
    MD.H[3] = 0xa54ff53a;
        MD.H[4] = 0x510e527f;
    MD.H[5] = 0x9b05688c;
    MD.H[6] = 0x1f83d9ab;
    MD.H[7] = 0x5be0cd19;
}
//处理512比特数据，返回信息摘要
Message_Digest SHA256::DEAL(UInt32 M[16]){
    int i;
    UInt32 T1=0,T2=0;
    UInt32 W[64]={0};
    UInt32 A=0,B=0,C=0,D=0,E=0,F=0,G=0,H=0;
    for(i=0;i<16;i++){
        W[i] = M[i];
    }
    for(i=16;i<64;i++){
        W[i] = SSigma_1(W[i-2])+W[i-7]+SSigma_0(W[i-15])+W[i-16];
    }
    A = MD.H[0];
    B = MD.H[1];
    C = MD.H[2];
    D = MD.H[3];
    E = MD.H[4];
    F = MD.H[5];
    G = MD.H[6];
    H = MD.H[7];
    cout<<"初始:";
    cout<<hex<<A<<" "<<B<<" "<<C<<" "<<D<<" "<<E<<" "<<F<<" "<<G<<" "<<H<<endl;
    for(i=0;i<64;i++){
        T1 = H + LSigma_1(E) + Conditional(E, F, G) + K[i] + W[i];
        T2 = LSigma_0(A) + Majority(A, B, C);
        H = G;
        G = F;
        F = E;
        E = D + T1;
        D = C;
        C = B;
        B = A;
        A = T1 + T2;
        cout<<dec<<i<<":";
        cout<<hex<<A<<" "<<B<<" "<<C<<" "<<D<<" "<<E<<" "<<F<<" "<<G<<" "<<H<<endl;
    }
    MD.H[0]=(MD.H[0]+A) & 0xFFFFFFFF;
    MD.H[1]=(MD.H[1]+B) & 0xFFFFFFFF;
    MD.H[2]=(MD.H[2]+C) & 0xFFFFFFFF;
    MD.H[3]=(MD.H[3]+D) & 0xFFFFFFFF;
    MD.H[4]=(MD.H[4]+E) & 0xFFFFFFFF;
    MD.H[5]=(MD.H[5]+F) & 0xFFFFFFFF;
    MD.H[6]=(MD.H[6]+G) & 0xFFFFFFFF;
    MD.H[7]=(MD.H[7]+H) & 0xFFFFFFFF;
 
    return MD;
}
//右旋转
UInt32 SHA256::ROTR(UInt32 W,int n){
    return ((W >> n) & 0xFFFFFFFF) | (W) << (32-(n));
}
//左旋转
UInt32 SHA256::ROTL(UInt32 W,int n){
    return ((W << n) & 0xFFFFFFFF) | (W) >> (32-(n));
}
//右移位
UInt32 SHA256::SHR(UInt32 W,int n){
    return ((W >> n) & 0xFFFFFFFF);
}
//压缩+显示
void compress(){
    int i;
    M_D = sha256.DEAL(M);
    //cout<<"哈希值： ";
    //for(i=0;i<8;i++){
    //    cout<<hex<<M_D.H[i]<<" ";
    //}
    //cout<<endl;
}
Message_Digest sha256Compress(UChar Y[Max]){
    //填充+添加长度
    //x+1+d+l=|x|
    UInt32 i,j;
    UInt32 T1=0,T2=0,T3=0,T4=0;
    UChar temp[Max]={0};
    UInt64 x = strlen((char *)Y);//数据长度

    //UInt32 d = labs(55-x) % 64;   //填充长度
    UInt32 d = (55 - x)>=0?(55 - x):(x - 55);
    d = d % 64;

    UInt32 n = (x+8)/64+1; //分组数
    UInt32 m = x%64;       //最后组数据长度
    UInt32 l = 8;      
    cout<<"数据长度x:"<<int(x)<<" ";
    cout<<"填充长度d:"<<d<<" ";
    cout<<"分组数量n:"<<n<<" ";
    cout<<"最后长度m:"<<m<<endl;
    //不填充
    for(i=0;i<x;i++){
        temp[i] = Y[i];
    }
    //填充1次1000 0000
        temp[x] = 0x80;
    //填充d次0000 0000
    for(i=x+1;i<x+d+1;i++){
        temp[i] = 0x00;
    }
    //填充长度的63-0位
    for(i=1;i<=l;i++){
        temp[(n*64)-i] = (UChar)(8*x>>(i-1)*8);
    }
    //无符号字符转换为无符号整型
    for(i=0;i<Max/4;i++){
        for(j=0;j<4;j++){
            if(j==0)
                T1 = temp[4*i+j];
            if(j==1)
                T2 = temp[4*i+j];
            if(j==2)
                T3 = temp[4*i+j];
            if(j==3)
                T4 = temp[4*i+j];
        }
        W[i] = (T1<<24) + (T2<<16) + (T3<<8) +T4;
    }
    //显示16进制数据
    cout<<"16进制数据：";
    for(i=0;i<n*16;i++){
        cout<<hex<<" "<<W[i];
    }
    cout<<endl;
    //分组处理
    for(i=0;i<n;i++){
        cout<<"分组处理:"<<i+1<<endl;
        for(j=0;j<16;j++){
            M[j] = W[(i*16)+j];
        }
        compress();//sha256压缩
    }
    return M_D;
}