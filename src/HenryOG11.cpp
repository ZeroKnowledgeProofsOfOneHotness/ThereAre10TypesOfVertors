/*
 *Date: 2019/07/02
 *Project: Proof Of Concept for: There are 10 Types of Vectors (and Polynomials)
 *File: HenryOG11.cc
 *  Contains Class and method implementations of data structures needed for (HV)ZKPoK for One-Hotness, using a linear approach simulating the openings to zero
 */
#include"HenryOG11.hpp"

ZKP_Prover_Or::ZKP_Prover_Or(Pedersen& P,Pedersen_Commitment C_d,vector<ZZ_p> others,uint location):P(P)
{
    this->C_d=C_d;
    this->others=others;
    this->location=location;
}

ZKP_Prover_Or::~ZKP_Prover_Or()
{

}

vector<Pedersen_Commitment> ZKP_Prover_Or::get_commitments()
{
    bn_t zero;
    bn_new(zero);
    bn_zero(zero);
    for(uint j=0; j<this->others.size();j++)
    {
        bn_t v1j;
        bn_new(v1j);
        
        this->V1.push_back(random_ZZ_p());
        conv(v1j,this->V1[j]);


        if(j==this->location){
            this->C.push_back(ZZ_p(0));
            this->C1.push_back(this->P.commit(zero,v1j));
        }else{
            this->C.push_back(random_ZZ_p());
           
            ZZ_p x,y;
            bn_t bn_x,bn_y;
            bn_new(bn_x);bn_new(bn_y);
            this->C_d.get_message(bn_x);
            this->C_d.get_randomKey(bn_y);
            conv(x,bn_x);
            conv(y,bn_y);

            conv(bn_x,(x-this->others[j])*(-this->C[j]));
            conv(bn_y,y*(-this->C[j])+this->V1[j]);

            this->C1.push_back(this->P.commit(bn_x,bn_y));
        }
    }
    for(uint j=0;j<this->C.size();j++)
    {
        if(j!=this->location)
        {
            this->C[this->location]-=this->C[j];
        }
    }
    return this->C1;
}

void ZKP_Prover_Or::set_challenge(ZZ_p challenge)
{
    /*To-Do */
    this->C[this->location]+=challenge;
}

tuple<vector<ZZ_p>,vector<ZZ_p>> ZKP_Prover_Or::get_verification()
{
    bn_t r1;
    bn_new(r1);
    this->C_d.get_randomKey(r1);
    ZZ_p R1;
    conv(R1,r1);
    this->V1[this->location]=this->V1[this->location]+this->C[this->location]*R1;
    return make_tuple(this->V1,this->C);
}

ZKP_Verifier_Or::ZKP_Verifier_Or(Pedersen& P,Pedersen_Commitment C_d, vector<ZZ_p> others):P(P)
{
    this->C_d=C_d;
    this->others=others;
    random(this->challenge);
    bn_t zero;
    bn_new(zero);
    bn_zero(zero);
    for(uint j=0;j<this->others.size();j++)
    {
        bn_t lambda;
        bn_new(lambda);
        conv(lambda,this->others[j]);
        this->A.push_back(this->C_d-this->P.commit(lambda,zero));
    }
}

ZKP_Verifier_Or::~ZKP_Verifier_Or()
{

}

void ZKP_Verifier_Or::set_commitments(vector<Pedersen_Commitment> commitments)
{
    this->C1=commitments;
}

ZZ_p ZKP_Verifier_Or::get_challenge()
{
    return this->challenge;
}

void ZKP_Verifier_Or::set_verification(tuple<vector<ZZ_p>,vector<ZZ_p>> verification)
{
    this->V1=get<0>(verification);
    this->C=get<1>(verification);
}

bool ZKP_Verifier_Or::accept()
{
    for(uint j=0;j<this->others.size();j++)
    {
        bn_t c,v1,zero;
        bn_new(c);bn_new(v1);bn_new(zero);
        bn_zero(zero);
        conv(c,this->C[j]);
        conv(v1,this->V1[j]);
        if(!((P.commit(zero,v1))==this->C1[j]+this->A[j]*c))
        {
            cout<<"1"<<endl;
            cout<<"Failed on i="<<j<<endl;
            return false;
        }
    }
    ZZ_p temp(0);
    for(uint j=0;j<this->C.size();j++)
    {
        temp+=this->C[j];
    }
    if(temp!=this->challenge)
    {
        cout<<"3"<<endl;
        return false;
    }
    return true;
}

ZKP_Prover_Vector_HenryOG11::ZKP_Prover_Vector_HenryOG11(Pedersen& P, vector<Pedersen_Commitment> Commitments,uint location):P(P)
{
    auto stime = chrono::high_resolution_clock::now();
    this->Commitments=Commitments;
    this->location=location;
    this->creation_timer = chrono::high_resolution_clock::now()-stime;
}

ZKP_Prover_Vector_HenryOG11::~ZKP_Prover_Vector_HenryOG11()
{
    delete this->prover;
}

void ZKP_Prover_Vector_HenryOG11::set_vector_challenge(vector<ZZ_p> arrChallenge)
{
    auto stime = chrono::high_resolution_clock::now();
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
    prover = new ZKP_Prover_Or(P,d,this->arrChallenge,this->location);
    this->set_vector_challenge_timer = chrono::high_resolution_clock::now() - stime;
}

vector<Pedersen_Commitment> ZKP_Prover_Vector_HenryOG11::get_commitments()
{
    auto stime = chrono::high_resolution_clock::now();
    auto temp = this->prover->get_commitments();
    this->get_commit_timer = chrono::high_resolution_clock::now()-stime;
    return temp;
}

void ZKP_Prover_Vector_HenryOG11::set_challenge(ZZ_p challenge)
{
    auto stime = chrono::high_resolution_clock::now();
    this->prover->set_challenge(challenge);
    this->set_challenge_timer = chrono::high_resolution_clock::now() -stime;
}

 tuple<vector<ZZ_p>,vector<ZZ_p>> ZKP_Prover_Vector_HenryOG11::get_verification()
 {
    auto stime = chrono::high_resolution_clock::now();
    auto temp = this->prover->get_verification();
    this->get_verify_timer = chrono::high_resolution_clock::now()-stime;
    return temp;
 }

tuple<chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>> ZKP_Prover_Vector_HenryOG11::get_timers()
{
    return make_tuple(this->creation_timer,this->set_vector_challenge_timer,this->get_commit_timer,this->set_challenge_timer,this->get_verify_timer);
}

ZKP_Verifier_Vector_HenryOG11::ZKP_Verifier_Vector_HenryOG11(Pedersen& P,vector<Pedersen_Commitment> Commitments,uint lambda):P(P)
{
    auto stime =chrono::high_resolution_clock::now();
    this->Commitments=Commitments;
    this->lambda=lambda;
    bn_t zero;
    bn_new(zero);
    bn_zero(zero);
    Pedersen_Commitment d=P.commit(zero,zero);
    for(uint i=0;i<this->Commitments.size();i++)
    {
        ZZ_p random_val=genRandom(this->lambda);
        this->arrChallenge.push_back(random_val);
    }
    d=multi_exp_sub(P,Commitments,arrChallenge,5,2);
    this->verifier= new ZKP_Verifier_Or(P,d,this->arrChallenge);
    this->creation_timer=chrono::high_resolution_clock::now()-stime;
}

ZKP_Verifier_Vector_HenryOG11::~ZKP_Verifier_Vector_HenryOG11()
{
    delete this->verifier;
}

vector<ZZ_p> ZKP_Verifier_Vector_HenryOG11::get_vector_challenge()
{
    return this->arrChallenge;
}

void ZKP_Verifier_Vector_HenryOG11::set_commitments(vector<Pedersen_Commitment> Commitments)
{
    auto stime =chrono::high_resolution_clock::now();
    this->verifier->set_commitments(Commitments);
    this->set_commit_timer = chrono::high_resolution_clock::now() -stime;
}

ZZ_p ZKP_Verifier_Vector_HenryOG11::get_challenge()
{
    return this->verifier->get_challenge();
}

void ZKP_Verifier_Vector_HenryOG11::set_verification(tuple<vector<ZZ_p>,vector<ZZ_p>> verification)
{
    auto stime = chrono::high_resolution_clock::now();
    this->verifier->set_verification(verification);
    this->set_verify_timer = chrono::high_resolution_clock::now() -stime;
}

bool ZKP_Verifier_Vector_HenryOG11::accept()
{
    auto stime =chrono::high_resolution_clock::now();
    auto temp = this->verifier->accept();
    this->accept_timer = chrono::high_resolution_clock::now()-stime;
    return temp;
}

tuple<chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>> ZKP_Verifier_Vector_HenryOG11::get_timers()
{
    return make_tuple(this->creation_timer,this->set_commit_timer,this->set_verify_timer,this->accept_timer);
}