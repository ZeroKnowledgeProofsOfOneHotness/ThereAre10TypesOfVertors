/*
 *Date: 2019/07/02
 *Project: Proof Of Concept for: There are 10 Types of Vectors (and Polynomials)
 *File: utils.cc
 *  File contains the function implementation of functions defined in untils.hpp
 */
#include"utils.hpp"
#include<iterator>
#include<chrono>

Pedersen_Commitment horners_method(vector<Pedersen_Commitment> arr,size_t n,bn_t value)
{
    //Note that a multi exp was actually quicker
    ZZ_p x;
    conv(x,value);
    ZZ_p iter(1);
    vector<ZZ_p> exponents;
    Pedersen P;
    for(uint i=0;i<n;i++)
    {
        exponents.push_back(iter);
        iter=iter*x;
    }
    return multi_exp_sub(P,arr,exponents,5,2);
}

void conv(bn_t out, ZZ_p in)
{
    ZZ temp=rep(in);
    long len = NumBytes(temp);
    uint8_t bin[32] = {0};

    BytesFromZZ(bin,temp,len);
    int i=0;
    int j=31;
    while(i<j){
        uint8_t temp;
        temp = bin[i];
        bin[i]=bin[j];
        bin[j]=temp;
        j--;
        i++;
    }
    bn_read_bin(out,bin,32);
}

void conv(ZZ_p& out, bn_t in)
{
    uint8_t bin[32]={0};
    bn_write_bin(bin,32,in);
    int i=0;
    int j=31;
    while(i<j){
        uint8_t temp;
        temp = bin[i];
        bin[i]=bin[j];
        bin[j]=temp;
        j--;
        i++;
    }
    ZZ temp;
    ZZFromBytes(temp,bin,32);
    conv(out,temp);
}

void conv(ZZ& out,bn_t in)
{
    char str[80];
    ZZ value;
    bn_write_str(str,80,in,10);
    conv(out,str);
}

//Like it doesn't really use horner method... but I am okay with that.
ZZ_p horners_method(vector<ZZ_p> coefficients,ZZ_p t)
{
    ZZ_pX f;
    f.SetLength(coefficients.size());
    for(uint i=0;i < coefficients.size();i++)
    {
        f[i]=coefficients[i];
    }
    return eval(f,t);
}

int max_bits_of(vector<ZZ_p> exponents)
{
    uint max =0;
    for(uint i=0;i<exponents.size();i++)
    {
        if(NumBits(rep(exponents[i]))>max)
        {
            max=NumBits(rep(exponents[i]));
        }
    }
    return max;
}

Pedersen_Commitment multi_exp(Pedersen& P,vector<Pedersen_Commitment> commitments,vector<ZZ_p> exponents, const uint window_size)
{
    //Create precomputation table.
    uint size = commitments.size();
    uint number = (size/window_size);
    uint power = pow(2,window_size);
    bn_t zero;
    bn_new(zero);
    bn_zero(zero);
    Pedersen_Commitment return_value=P.commit(zero,zero);
    Pedersen_Commitment **precomp= new Pedersen_Commitment*[number];
    for(uint i=0; i<number;i++)
    {
        precomp[i] = new Pedersen_Commitment[power];
        for(uint j=0; j<power;j++)
        {
            precomp[i][j]=return_value;
        }
    }
    for(uint i=0; i<number;i++)
    {
        precomp[i][0]=return_value;
        for(uint j=0;j<window_size;j++)
        {
            int val=0x1<<j;
            precomp[i][val]=commitments[i*window_size+j];
        }
        for(uint j=0;j<power;j++)
        {
            if(precomp[i][j]==return_value)
            {
                for(uint k=0;k<window_size;k++)
                {
                    //Found first bit
                    if(((0x1<<k)&j)!=0)
                    {
                        precomp[i][j]=precomp[i][0x1<<k]+precomp[i][j-(0x1<<k)];
                    }
                }
            }
        }
    }

    for(int i=max_bits_of(exponents); i>=0;i--)
    {
        return_value=return_value+return_value;
        for(uint k=0;k<number;k++){
            int temp=0;
            for(uint j=0;j<window_size;j++)
            {
                temp+=bit(rep(exponents[k*window_size+j]),i)<<j;
            }

            return_value=return_value+precomp[k][temp];
        }
    }

    for(uint i=0; i<number;i++)
    {
        delete[] precomp[i];
    }
    delete[] precomp;
    //This is small just add them to the end.
    for(uint i=number*window_size;i<commitments.size();i++)
    {
        bn_t num;
        bn_new(num);
        conv(num,exponents[i]);
        return_value= return_value+commitments[i]*num;
    }

    return return_value;
}

Pedersen_Commitment multi_exp_sub(Pedersen& P, vector<Pedersen_Commitment> commitments, vector<ZZ_p> exponents,const int window_size, const int chunks)
{
    int segment = commitments.size()/chunks;

    bn_t zero;
    bn_new(zero);
    bn_zero(zero);
    Pedersen_Commitment total=P.commit(zero,zero);
    for(int i=0;i<chunks;i++)
    {
        total = multi_exp(P,vector<Pedersen_Commitment>(commitments.begin()+(i*segment),commitments.begin()+((i+1)*segment)),vector<ZZ_p>(exponents.begin()+(i*segment),exponents.begin()+((i+1)*segment)),window_size)+total;
    }
    total=total+multi_exp(P,vector<Pedersen_Commitment>(commitments.begin()+(chunks*segment),commitments.end()),vector<ZZ_p>(exponents.begin()+(chunks*segment),exponents.end()),window_size);

    return total;
}

ZZ_p genRandomT(uint lambda,uint bitlength)
{
    return genRandom(lambda+2*bitlength);
}

ZZ_p genRandom(uint lambda)
{
    ZZ_p returnval=conv<ZZ_p>(RandomBits_ZZ(lambda));
    return returnval;
}

