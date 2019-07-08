/*
 *Date: 2019/07/02
 *Project: Proof Of Concept for: There are 10 Types of Vectors (and Polynomials)
 *File: ThisWork.cc
 *  Contains Class and method implementations of data structures needed for (HV)ZKPoK for One-Hotness, using the new protocol using the evaluation of polynomails to prove knowledge of witnesses
 */

#include"ThisWork.hpp"
ZKP_Prover_Vector_ThisWork::ZKP_Prover_Vector_ThisWork(Pedersen &P, vector<Pedersen_Commitment> Commitments, uint location):P(P)
{
    auto stime=chrono::high_resolution_clock::now();
    this->Commitments=Commitments;
    this->location=location;
    this->bitlength=(uint) ceil(log2(this->Commitments.size()+1));
    this->creation_timer = chrono::high_resolution_clock::now()-stime;
}
ZKP_Prover_Vector_ThisWork::~ZKP_Prover_Vector_ThisWork()
{

}

tuple<chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>> ZKP_Prover_Vector_ThisWork::get_timers()
{
    return make_tuple(creation_timer,set_t_timer,get_commit_timer,set_challenge_timer,get_verify_timer);
}

void ZKP_Prover_Vector_ThisWork::set_t_challenge(ZZ_p t_challenge)
{
    auto stime=chrono::high_resolution_clock::now();
    //Choose randomness
    random(this->r,this->bitlength);
    random(this->s,this->bitlength);
    random(this->t,this->bitlength);
    random(this->epsilon,this->bitlength);
    random(this->gamma,this->bitlength+1);
    random(this->delta,this->bitlength+1);
    //Set the polynomial challenge
    this->t_challenge=t_challenge;
    //Compute the polynomial
    vector<ZZ_p> randoms;
    for(uint i=0;i<this->Commitments.size();i++)
    {
        ZZ_p temp;
        bn_t r;
        bn_new(r);
        this->Commitments[i].get_randomKey(r);
        conv(temp,r);
        randoms.push_back(temp);
    }
    this->gamma[this->bitlength] = horners_method(randoms,t_challenge);

    this->d.SetLength(this->bitlength);
    this->a.SetLength(this->bitlength);
    ZZ_p iterator =this->t_challenge;
    for(uint j=0;j<this->bitlength;j++)
    {
        d[j]=inv(iterator-1);
        a[j]=(iterator-1)*(0x1&(this->location>>j))+1;
        iterator*=iterator;
    }
    this->set_t_timer = chrono::high_resolution_clock::now()-stime;
}

tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>> ZKP_Prover_Vector_ThisWork::get_commitments()
{
    auto stime=chrono::high_resolution_clock::now();
    vector<Pedersen_Commitment> C,C_prime,A,A_prime,A_bar;
    for(uint j=0;j<this->bitlength;j++)
    {
        C.push_back(this->P.commit(this->a[j],this->r[j]));
        A.push_back(this->P.commit(this->s[j],this->t[j]));
        A_bar.push_back(this->P.commit(this->s[j]*(this->a[j]-1)*this->d[j]*this->d[j],this->epsilon[j]));
    }
    ZZ_p a_product_series=this->a[0];
    for(uint j=2;j<this->bitlength+1;j++)
    {
        A_prime.push_back(this->P.commit(this->s[j-1]*a_product_series,this->delta[j]));
        a_product_series*=this->a[j-1];
        if(j<this->bitlength){
            C_prime.push_back(this->P.commit(a_product_series,this->gamma[j]));
        }
    }
    this->get_commit_timer = chrono::high_resolution_clock::now() -stime;
    return make_tuple(C,A,A_bar,C_prime,A_prime);
}

tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>> ZKP_Prover_Vector_ThisWork::get_verification()
{
    auto stime=chrono::high_resolution_clock::now();
    vector<ZZ_p> v,u,w,z;
    for(uint j=0;j<this->bitlength;j++)
    {
        v.push_back(this->s[j]+this->a[j]*this->challenge);
        u.push_back(this->t[j]+this->r[j]*this->challenge);
        w.push_back(this->epsilon[j]+this->r[j]*this->d[j]*(this->challenge-((v[j]-this->challenge)*this->d[j])));
    }
    for(uint j=2;j<this->bitlength+1;j++)
    {
        if(j!=2)
        {
            z.push_back((-this->gamma[j-1]*v[j-1])+this->delta[j]+this->gamma[j]*this->challenge);
        }else{
            z.push_back((-this->r[j-2]*v[j-1])+this->delta[j]+this->gamma[j]*this->challenge);
        }
        
    }
    this->get_verify_timer = chrono::high_resolution_clock::now()-stime;
    return make_tuple(v,u,w,z);
}

void ZKP_Prover_Vector_ThisWork::set_challenge(ZZ_p challenge)
{
    auto stime = chrono::high_resolution_clock::now();
    this->challenge=challenge;
    this->set_challenge_timer = chrono::high_resolution_clock::now()-stime;
}

ZKP_Verifier_Vector_ThisWork::ZKP_Verifier_Vector_ThisWork(Pedersen &P, vector<Pedersen_Commitment> Commitments,uint lambda):P(P)
{
    auto stime = chrono::high_resolution_clock::now();
    this->Commitments=Commitments;
    this->bitlength=(uint) ceil(log2(this->Commitments.size()+1));
    this->lambda=lambda;
    this->t_challenge=genRandomT(this->lambda,this->bitlength);
    this->challenge=genRandom(this->lambda);
    bn_t t;
    bn_new(t);
    conv(t,this->t_challenge);
    this->poly_commit=horners_method(this->Commitments,this->Commitments.size(),t);
    this->creation_timer = chrono::high_resolution_clock::now() - stime;
}

ZKP_Verifier_Vector_ThisWork::~ZKP_Verifier_Vector_ThisWork()
{

}


ZZ_p ZKP_Verifier_Vector_ThisWork::get_t_challenge()
{
    return this->t_challenge;
}

ZZ_p ZKP_Verifier_Vector_ThisWork::get_challenge()
{
    return this->challenge;
}

void ZKP_Verifier_Vector_ThisWork::set_commitments(tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>> proof)
{
    auto stime = chrono::high_resolution_clock::now();
    this->proof=proof;
    this->set_commit_timer = chrono::high_resolution_clock::now()-stime;
}

void ZKP_Verifier_Vector_ThisWork::set_verification(tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>> verification)
{
    auto stime = chrono::high_resolution_clock::now();
    this->v=get<0>(verification);
    this->u=get<1>(verification);
    this->w=get<2>(verification);
    this->z=get<3>(verification);
    this->set_verify_timer = chrono::high_resolution_clock::now()-stime;
}

bool ZKP_Verifier_Vector_ThisWork::accept()
{
    auto stime = chrono::high_resolution_clock::now();
    bn_t bn_challenge;
    bn_new(bn_challenge);
    Pedersen_Commitment g=P.commit(ZZ_p(1),ZZ_p(0));
    conv(bn_challenge,this->challenge);
    vector<Pedersen_Commitment> C,C_prime,A,A_prime,A_bar;
    C=get<0>(this->proof);
    A=get<1>(this->proof);
    A_bar=get<2>(this->proof);
    C_prime=get<3>(this->proof);
    A_prime=get<4>(this->proof);
    C_prime.push_back(poly_commit);

    ZZ_p iterator = t_challenge;
    for(uint j=0;j<this->bitlength;j++)
    {
        bn_t temp_power;
        bn_new(temp_power);
        ZZ_p dj=inv(iterator-1);
        conv(temp_power,dj*(this->challenge-((v[j]-this->challenge)*dj)));

        if(!(A[j]+C[j]*bn_challenge==this->P.commit(this->v[j],this->u[j])))
        {
            cout<<"FAILED ZKPoK for the discrete log on j="<<j<<endl;
            return false;
        }
        if(!(A_bar[j]+ (C[j]-g)*temp_power==this->P.commit(ZZ_p(0),this->w[j])))
        {
            this->P.commit(ZZ_p(0),this->w[j]).print();
            (A_bar[j]+ (C[j]+g)*temp_power).print();
            cout<<"FAILED ZKPoK for the opening to 1 or t^2^j, where j="<<j<<endl;
            return false;
        }
        iterator*=iterator;
    }
    
    {
        bn_t temp_power;
        bn_new(temp_power);
        conv(temp_power,this->v[1]);
        if(!(A_prime[0]+C_prime[0]*bn_challenge==C[0]*temp_power+this->P.commit(ZZ_p(0),this->z[0]))){
            cout<<"Failed ZKPoK for multiplication on j=0"<<endl;
        }
    }
    
    for(uint j=1;j<this->bitlength-1;j++)
    {
        bn_t temp_power;
        bn_new(temp_power);
        conv(temp_power,this->v[j+1]);
        if(!(A_prime[j]+C_prime[j]*bn_challenge==(C_prime[j-1]*temp_power)+this->P.commit(ZZ_p(0),this->z[j])))
        {
            (A_prime[j]+C_prime[j]*bn_challenge).print();
            ((C_prime[j-1]*temp_power)+this->P.commit(ZZ_p(0),this->z[j])).print();
            cout<<"Failed ZKPoK for multiplication on j="<<j<<endl;
            return false;
        }
    }

    this->accept_timer = chrono::high_resolution_clock::now() - stime;
    return true;
}

tuple<chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>> ZKP_Verifier_Vector_ThisWork::get_timers()
{
    return make_tuple(this->creation_timer,this->set_commit_timer,this->set_verify_timer,this->accept_timer);
}