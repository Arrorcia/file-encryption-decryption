#include<string.h>
#include<iostream>
#include"sha256.h"
using namespace std;
 
//主函数
int main(){
    UChar Y[Max];
    cout<<"请输入要加密的字符串（最大"<<Max<<"个）："<<endl;
    cin>>Y;
    sha256Compress(Y);
    return 0;
}