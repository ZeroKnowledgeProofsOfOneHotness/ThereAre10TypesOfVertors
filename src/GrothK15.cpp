/*
 *Date: 2019/07/02
 *Project: Proof Of Concept for: There are 10 Types of Vectors (and Polynomials)
 *File: GRothK15.cc
 *  Contains Class and method implementations of data structures needed for (HV)ZKPoK for One-Hotness, using the protocol of membership described by Groth and Kolhlweiss
 */

#include"GrothK15.hpp"
#include"pedersen.hpp"
#include"utils.hpp"
#include<vector>
#include<chrono>
using namespace NTL;
using namespace std;

ZKP_Prover_1_TO_M::ZKP_Prover_1_TO_M(Pedersen& P,Pedersen_Commitment C,vector<ZZ_p> Commitments,int loc):P(P)
{
    this->location=loc;
    this->Commitments=Commitments;
    this->C=C;
    this->bitlength=(int) ceil(log2(this->Commitments.size()+1));
    for(int j=0; j<this->bitlength;j++)
    {
        this->rj.push_back(random_ZZ_p());
        this->aj.push_back(random_ZZ_p());
        this->sj.push_back(random_ZZ_p());
        this->tj.push_back(random_ZZ_p());
        this->pk.push_back(random_ZZ_p());
    }
    //Now we need to gen all the polynomials.
    for(uint i=0;i<Commitments.size();i++)
    {
        ZZ_pX poly;
        poly=1;
        for(int j=0;j<this->bitlength;j++)
        {
            //must look at the bits of i and loc;
            int l=((loc>>j)&0b1);
            int ij=(i>>j&0b1);
            ZZ_pX temp;
            temp.SetLength(2);
            if(ij==1){
                temp[0]=aj[j];
                if(l==1)
                {
                    temp[1]=1;
                }
                else
                {
                    temp[1]=0;
                }
            }
            else
            {
                temp[0]= -aj[j];
                if(l==0)
                {
                    temp[1]=1;
                }
                else 
                {
                    temp[1]=0;
                }
            }
            poly=poly*temp;
           
        }
        this->pi.push_back(poly);
    }
}

tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>> ZKP_Prover_1_TO_M::get_commitments()
{
    vector<Pedersen_Commitment> Clj;
    vector<Pedersen_Commitment> Caj;
    vector<Pedersen_Commitment> Cbj;
    vector<Pedersen_Commitment> Cdk;

    vec_ZZ_p dk;
    dk.SetLength(this->bitlength);
    vec_ZZ_p phik;
    phik.SetLength(this->bitlength);
    vec_ZZ_p xk;
    random(xk,this->bitlength);
    bn_t bn_r;
    ZZ_p r;
    bn_new(bn_r);
    this->C.get_randomKey(bn_r);
    conv(r,bn_r);
    for(int j=0;j<this->bitlength;j++)
    {
        dk[j]=0;
        phik[j]=0;
        for(uint i=0;i<this->Commitments.size();i++)
        {
            ZZ_p pixk;
            pixk=eval(pi[i],xk[j]);
            dk[j]=this->Commitments[i]*pixk+dk[j];
            phik[j]=r*pixk+phik[j];

        }
        bn_t gaml;
        ZZ_p temp1;
        power(temp1,xk[j],this->bitlength);
        phik[j]=phik[j]-temp1*r;

    }

    ZZ_pX d,phi;
    interpolate(d,xk,dk);
    interpolate(phi,xk,phik);

    for(int j = 0;j<this->bitlength;j++)
    {
        bn_t r,a,s,t,temp,zero,one,l;
        bn_new(temp);
        bn_new(l);
        bn_new(one);
        bn_new(zero);
        bn_zero(zero);
        bn_new(a);bn_new(r);bn_new(s);bn_new(t);
        bn_read_str(one,"1",1,10);
        int lj=(this->location>>j &0b1);
        conv(r,this->rj[j]);
        conv(a,this->aj[j]);
        conv(s,this->sj[j]);
        conv(t,this->tj[j]);

        if(lj==0)
        {
            bn_copy(l,zero);
        }
        else
        {
            bn_copy(l,one);
        }
        bn_mul(temp,a,l);
        Clj.push_back(this->P.commit(l,r));
        Caj.push_back(this->P.commit(a,s));
        Cbj.push_back(this->P.commit(temp,t));
        ZZ_p d_k=coeff(d,j),phi_k=coeff(phi,j);
        bn_t bn_dk,bn_phik;
        bn_new(bn_dk);
        bn_new(bn_phik);
        conv(bn_dk,d_k);
        conv(bn_phik,phi_k+this->pk[j]);
        Cdk.push_back(this->P.commit(bn_dk,bn_phik));
    }
    return make_tuple(Clj,Caj,Cbj,Cdk);
}

void ZKP_Prover_1_TO_M::set_challenge(ZZ_p challenge)
{
    this->challenge=challenge;
}

tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,ZZ_p> ZKP_Prover_1_TO_M::get_verification()
{
    vector<ZZ_p> fj;
    vector<ZZ_p> Zaj;
    vector<ZZ_p> Zbj;
    ZZ_p Zd,r(0);

    for(int j = 0;j<this->bitlength;j++)
    {
        int lj=(this->location>>j&0b1);
        fj.push_back(lj*this->challenge+this->aj[j]);
        Zaj.push_back(this->rj[j]*this->challenge+this->sj[j]);
        Zbj.push_back(this->rj[j]*(this->challenge - fj[j])+this->tj[j]);
    }

    ZZ_pX ZdX;
    ZdX.SetLength(this->bitlength+1);
    for(int k=0;k<this->bitlength;k++)
    {
        ZdX[k]=-this->pk[k];
    }

    bn_t randomKey;
    bn_new(randomKey);
    this->C.get_randomKey(randomKey);
    conv(r,randomKey);
    ZdX[this->bitlength]=r;
    Zd = eval(ZdX,this->challenge);
    return make_tuple(fj,Zaj,Zbj,Zd);
}



ZKP_Prover_1_TO_M::~ZKP_Prover_1_TO_M()
{

}

ZKP_Verifier_1_TO_M::ZKP_Verifier_1_TO_M(Pedersen& P,vector<Pedersen_Commitment> Commitments,vector<ZZ_p> values, Pedersen_Commitment Cd):P(P)
{
    this->bitlength=(int) ceil(log2(Commitments.size()+1));
    this->Commitments=Commitments;
    random(this->challenge);
    this->values=values;
    this->Cd=Cd;
}

ZZ_p ZKP_Verifier_1_TO_M::get_challenge()
{
    return this->challenge;
}

void ZKP_Verifier_1_TO_M::set_commitments(tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>> Proof_Commitments)
{
    this->Proof_Commitments=Proof_Commitments;
}

void ZKP_Verifier_1_TO_M::set_verification(tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,ZZ_p> Proof_Verification)
{
    this->fj=get<0>(Proof_Verification);
    this->Zaj=get<1>(Proof_Verification);
    this->Zbj=get<2>(Proof_Verification);
    this->Zd=get<3>(Proof_Verification);
}

bool ZKP_Verifier_1_TO_M::accept()
{
    //Unpack
    vector<Pedersen_Commitment> Clj=get<0>(this->Proof_Commitments);
    vector<Pedersen_Commitment> Caj=get<1>(this->Proof_Commitments);
    vector<Pedersen_Commitment> Cbj=get<2>(this->Proof_Commitments);
    vector<Pedersen_Commitment> Cdk=get<3>(this->Proof_Commitments);
    
    bn_t zero,c;
    bn_new(zero);
    bn_zero(zero);
    bn_new(c);
    conv(c,this->challenge);
    for(int j = 0; j<this->bitlength;j++)
    {
        bn_t f,Za,Zb,x_minus_f;
        bn_new(f);
        bn_new(Za);
        bn_new(Zb);
        bn_new(x_minus_f);
        
        conv(f,this->fj[j]);
        conv(Za,this->Zaj[j]);
        conv(Zb,this->Zbj[j]);
        conv(x_minus_f,this->challenge-this->fj[j]);


        
        if(!((Clj[j]*c+Caj[j])==P.commit(f,Za)))
        {
            cout<<"Failed 1 j="<<j<<endl;
            cout<<"Test 1:"<<endl;
            (Clj[j]*c+Caj[j]).print();
            P.commit(f,Za).print();
            return false;
        }
        if(!((Clj[j]*x_minus_f+Cbj[j])==P.commit(zero,Zb)))
        {
            cout<<"Failed 2 j="<<j<<endl;
            cout<<"Test 2:"<<endl;
            (Clj[j]*x_minus_f+Cbj[j]).print();
            P.commit(zero,Zb).print();
            return false;
        }

    }

    ZZ_p tempMessage(0);
    ZZ_p tempExpon(0);
    for(uint i =0; i<this->Commitments.size();i++)
    {
        ZZ_p temp(1);
        for(int j=0;j<this->bitlength;j++)
        {
            if(((i>>j)&0b1)==1)
            {
                temp=temp*this->fj[j];
            }
            else
            {
                temp=temp*(this->challenge-this->fj[j]);
            }
        }
        tempMessage+=(this->values[i]*temp);
        tempExpon+=temp;
    }

    bn_t message,expon;
    bn_new(message);bn_new(expon);
    conv(message,-tempMessage);
    conv(expon,tempExpon);
    Pedersen_Commitment sum = P.commit(message,zero)+this->Cd*expon;
    ZZ_p iterator(1);
    for(int k=0; k<this->bitlength;k++)
    {
        bn_t bn_iterator;
        bn_new(bn_iterator);
        conv(bn_iterator,-iterator);
        sum=sum+Cdk[k]*bn_iterator;
        mul(iterator,iterator,this->challenge);
    }
    bn_t zd;
    conv(zd,this->Zd);
    if(!(sum==P.commit(zero,zd)))
    {
        cout<<"Failed The nasty"<<endl;
        cout<<"Testing the nasty"<<endl;
        sum.print();
        P.commit(zero,zd).print();
        return false;
    }
    return true;
}

ZKP_Verifier_1_TO_M::~ZKP_Verifier_1_TO_M()
{

}

ZKP_Prover_Membership::ZKP_Prover_Membership(Pedersen& P,Pedersen_Commitment Commitment, vector<ZZ_p> values,int location):P(P)
{
    this->Commitment = Commitment;
    this->values = values;
    this->location= location;
}

ZKP_Prover_Membership::~ZKP_Prover_Membership()
{
    delete this->prover;
}

tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>>ZKP_Prover_Membership::get_commitments()
{
    /*--Use only Witnessees-- */
    vector<ZZ_p> membership_commitments;
    bn_t bn_m;
    bn_new(bn_m);
    ZZ_p m;
    
    this->Commitment.get_message(bn_m);
    conv(m,bn_m);
    for(uint i=0; i<this->values.size();i++)
    {
        membership_commitments.push_back(m-this->values[i]);
    }
    this->prover = new ZKP_Prover_1_TO_M(this->P,this->Commitment,membership_commitments,this->location);
    return this->prover->get_commitments();
}

void ZKP_Prover_Membership::set_challenge(ZZ_p challenge)
{
    this->prover->set_challenge(challenge);
}

tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,ZZ_p> ZKP_Prover_Membership::get_verification()
{
    return this->prover->get_verification();
}

ZKP_Verifier_Membership::ZKP_Verifier_Membership(Pedersen& P,Pedersen_Commitment Commitment,vector<ZZ_p> values):P(P)
{
    this->Commitment=Commitment;
    this->values=values;
    vector<Pedersen_Commitment> membership_commitments;

    bn_t zero;
    bn_new(zero);
    bn_zero(zero);

    for(uint i=0;i<this->values.size();i++)
    {   
        bn_t lambda;
        bn_new(lambda);
        conv(lambda,this->values[i]);
        membership_commitments.push_back(this->Commitment-this->P.commit(lambda,zero));
    }
    this->verifier= new ZKP_Verifier_1_TO_M(this->P,membership_commitments,this->values,this->Commitment);
}

ZKP_Verifier_Membership::~ZKP_Verifier_Membership()
{
    delete this->verifier;
}
void ZKP_Verifier_Membership::set_commitments(tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>> commitments) 
{
    this->verifier->set_commitments(commitments);
}

ZZ_p ZKP_Verifier_Membership::get_challenge()
{
    return this->verifier->get_challenge();
}

void ZKP_Verifier_Membership::set_verification(tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,ZZ_p> verification)
{
    this->verifier->set_verification(verification);
}

bool ZKP_Verifier_Membership::accept()
{
    return this->verifier->accept();
}

ZKP_Prover_Vector_GrothK15::ZKP_Prover_Vector_GrothK15(Pedersen& P, vector<Pedersen_Commitment> Commitments,int location):P(P)
{
    auto stime = chrono::high_resolution_clock::now();
    this->Commitments=Commitments;
    this->location=location;
    this->creation_timer = chrono::high_resolution_clock::now() -stime;
}

ZKP_Prover_Vector_GrothK15::~ZKP_Prover_Vector_GrothK15()
{
    delete this->prover;
}

void ZKP_Prover_Vector_GrothK15::set_vector_challenge(vector<ZZ_p> arrChallenge)
{
    auto stime =chrono::high_resolution_clock::now();
    this->arrChallenge=arrChallenge;
    //Compute Dot product and sum.
    Pedersen_Commitment d;
    ZZ_p ai(0);
    ZZ_p ri(0);
    for(uint i=0;i<this->Commitments.size();i++)
    {
        bn_t m,r;
        bn_new(m);
        bn_new(r)
        ZZ_p ZZm;
        this->Commitments[i].get_message(m);
        this->Commitments[i].get_randomKey(r);
        conv(ZZm,m);
        ai=this->arrChallenge[i]*ZZm+ai;
        conv(ZZm,r);
        ri=this->arrChallenge[i]*ZZm+ri;
    }
    bn_t a,b;
    bn_new(a);bn_new(b);
    conv(a,ai);
    conv(b,ri);
    d=P.commit(a,b);
    prover = new ZKP_Prover_Membership(P,d,this->arrChallenge,this->location);
    this->set_vector_challenge_timer = chrono::high_resolution_clock::now()-stime;

}

tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>> ZKP_Prover_Vector_GrothK15::get_commitments()
{
    auto stime =chrono::high_resolution_clock::now();
    auto temp = this->prover->get_commitments();
    this->get_commit_timer = chrono::high_resolution_clock::now()-stime;
    return temp;
}

void ZKP_Prover_Vector_GrothK15::set_challenge(ZZ_p challenge)
{
    auto stime = chrono::high_resolution_clock::now();
    this->prover->set_challenge(challenge);
    this->set_challenge_timer = chrono::high_resolution_clock::now()-stime;
}

 tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,ZZ_p> ZKP_Prover_Vector_GrothK15::get_verification()
 {
    auto stime =chrono::high_resolution_clock::now();
    auto temp = this->prover->get_verification();
    this->get_verify_timer = chrono::high_resolution_clock::now() - stime; 
    return temp;
 }

tuple<chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>> ZKP_Prover_Vector_GrothK15::get_timers()
{
    return make_tuple(this->creation_timer,this->set_vector_challenge_timer,this->get_commit_timer,this->set_challenge_timer,this->get_verify_timer);
}


ZKP_Verifier_Vector_GrothK15::ZKP_Verifier_Vector_GrothK15(Pedersen& P,vector<Pedersen_Commitment> Commitments,uint lambda):P(P)
{
    auto stime = chrono::high_resolution_clock::now();
    this->Commitments=Commitments;
    this->lambda=lambda;
    bn_t zero;
    bn_new(zero);
    bn_zero(zero);
    Pedersen_Commitment d=P.commit(zero,zero);
    for(uint i=0;i<this->Commitments.size();i++)
    {
        ZZ_p randomVal = genRandom(this->lambda);
        this->arrChallenge.push_back(randomVal);
    }
    d=multi_exp_sub(P,Commitments,arrChallenge,5,1);
    this->verifier= new ZKP_Verifier_Membership(P,d,this->arrChallenge);
    this->creation_timer = chrono::high_resolution_clock::now()-stime;
}

ZKP_Verifier_Vector_GrothK15::~ZKP_Verifier_Vector_GrothK15()
{
    delete this->verifier;
}

vector<ZZ_p> ZKP_Verifier_Vector_GrothK15::get_vector_challenge()
{
    return this->arrChallenge;
}

void ZKP_Verifier_Vector_GrothK15::set_commitments(tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>> Commitments)
{
    auto stime = chrono::high_resolution_clock::now();
    this->verifier->set_commitments(Commitments);
    this->set_commit_timer = chrono::high_resolution_clock::now() -stime;
}

ZZ_p ZKP_Verifier_Vector_GrothK15::get_challenge()
{
    return this->verifier->get_challenge();
}

void ZKP_Verifier_Vector_GrothK15::set_verification(tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,ZZ_p> verification)
{
    auto stime = chrono::high_resolution_clock::now();
    this->verifier->set_verification(verification);
    this->set_verify_timer = chrono::high_resolution_clock::now() -stime;
}

bool ZKP_Verifier_Vector_GrothK15::accept()
{
    auto stime = chrono::high_resolution_clock::now();
    bool temp = this->verifier->accept();
    this->accept_timer= chrono::high_resolution_clock::now()-stime;
    return temp;
}

tuple<chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>> ZKP_Verifier_Vector_GrothK15::get_timers()
{
    return make_tuple(this->creation_timer,this->set_commit_timer,this->set_verify_timer,this->accept_timer);
}