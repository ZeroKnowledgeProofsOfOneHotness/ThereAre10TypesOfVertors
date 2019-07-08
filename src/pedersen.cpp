/*
 *Date: 2019/07/02
 *Project: Proof Of Concept for: There are 10 Types of Vectors (and Polynomials)
 *File: pedersen.cpp
 *  File contains the function implementation of functions defined in pedersen.hpp
 */
#include"utils.hpp"
Pedersen::Pedersen()
{
    /*--Create random number--*/
    bn_t random_value;
    bn_new(random_value);
    bn_rand(random_value,0,128);
    /*--Create Generators--*/ 
    ep_new(this->g);
    ep_new(this->h);
    ep_curve_get_gen(this->g);
    ep_mul_gen(this->h,random_value);
    /*--This was done for ease--*/
    bn_free(random_value);
}

Pedersen::~Pedersen()
{
    /*--Clean up--*/
    ep_free(this->h);
    ep_free(this->g);
}

Pedersen_Commitment Pedersen::commit(bn_t message,bn_t randomKey)
{
    /*--Temp vars --*/
    ep_t commitment;
    ep_new(commitment);
    /*--Create Commitment--*/
    ep_mul_sim(commitment,this->g,message,this->h,randomKey);

    return Pedersen_Commitment(message,randomKey,commitment);
}

Pedersen_Commitment Pedersen::commit(ZZ_p message,ZZ_p randomKey)
{
    bn_t bn_message,bn_randomKey;
    bn_new(bn_message);
    bn_new(bn_randomKey);
    conv(bn_message,message);
    conv(bn_randomKey,randomKey);
    return this->commit(bn_message,bn_randomKey);
}

Pedersen_Commitment::Pedersen_Commitment()
{
    bn_new(this->p);
    ep_curve_get_ord(this->p);
    bn_new(this->message);
    bn_new(this->randomKey);
    bn_zero(this->message);
    bn_zero(this->randomKey);
    ep_new(this->commitment);
    ep_set_infty(this->commitment);

}

Pedersen_Commitment::Pedersen_Commitment(bn_t message,bn_t randomKey,          \
                                         ep_t commitment)                             
{
    ep_new(this->commitment);
    bn_new(this->message);
    bn_new(this->randomKey);
    bn_copy(this->randomKey,randomKey);
    bn_copy(this->message,message);
    ep_copy(this->commitment,commitment);
    bn_new(this->p);
    ep_curve_get_ord(this->p);

}

Pedersen_Commitment::~Pedersen_Commitment()
{
    bn_free(this->message);
    bn_free(this->randomKey);
    ep_free(this->commitment);
}

void Pedersen_Commitment::print()
{
    std::cout<<"Printing the message"<<std::endl;
    bn_print(this->message);
    std::cout<<"Printing the Key"<<std::endl;
    bn_print(this->randomKey);
    std::cout<<"Printing the Commitment"<<std::endl;
    ep_norm(this->commitment,this->commitment);
    ep_print(this->commitment);
}

/*--Note that theses are to be homomorphic--*/
Pedersen_Commitment Pedersen_Commitment::operator+(const Pedersen_Commitment& other)
{
    bn_t newMessage,newRandomKey;
    ep_t newCommitment;
    ep_new(newCommitment);
    bn_new(newMessage);
    bn_new(newRandomKey);
    bn_add(newMessage,this->message,other.message);
    bn_mod(newMessage,newMessage,this->p);
    bn_add(newRandomKey,this->randomKey,other.randomKey);
    bn_mod(newRandomKey,newRandomKey,this->p);
    ep_add(newCommitment,this->commitment,other.commitment);
    return Pedersen_Commitment(newMessage,newRandomKey,newCommitment);
}
/*shared_ptr<Pedersen_Commitment> Pedersen_Commitment::operator+(const shared_ptr<Pedersen_Commitment> other)
{
    bn_t newMessage,newRandomKey;
    ep_t newCommitment;
    ep_new(newCommitment);
    bn_new(newMessage);
    bn_new(newRandomKey);
    bn_add(newMessage,this->message,other->message);

    bn_add(newRandomKey,this->randomKey,other->randomKey);
    ep_add(newCommitment,this->commitment,other->commitment);
    return make_shared<Pedersen_Commitment>(newMessage,newRandomKey,newCommitment);
}*/

bool Pedersen_Commitment::operator==(const Pedersen_Commitment& other)
{
    /*if(bn_cmp(this->message,other.message) != RLC_EQ)
    { 
        std::cout<<"Failed on message "<<std::endl;
        return false;
    }
    if(bn_cmp(this->randomKey,other.randomKey)!= RLC_EQ)
    {
        std::cout<<"Failed on key"<<std::endl;
        return false;
    }*/
    if(ep_cmp(this->commitment,other.commitment) == RLC_NE)
    {
        //std::cout<<"Failed on commitment"<<std::endl;
        return false;
    }
    return true;
}

Pedersen_Commitment Pedersen_Commitment::operator-(const Pedersen_Commitment& right)
{
    bn_t newMessage, newRandomKey;
    ep_t newCommitment;
    bn_new(newMessage);bn_new(newRandomKey);
    bn_sub(newMessage,this->message,right.message);
    bn_sub(newRandomKey,this->randomKey,right.randomKey);
    bn_mod(newMessage,newMessage,this->p);
    bn_mod(newRandomKey,newRandomKey,this->p);
    ep_new(newCommitment);
    ep_neg(newCommitment,right.commitment);
    ep_add(newCommitment,this->commitment,newCommitment);
    return Pedersen_Commitment(newMessage,newRandomKey,newCommitment);
}

Pedersen_Commitment Pedersen_Commitment::operator*(const bn_t other)
{
    bn_t newMessage, newRandomKey;
    ep_t newCommitment;
    bn_new(newMessage);
    bn_new(newRandomKey);
    bn_mul(newMessage,this->message,other);
    bn_mod(newMessage,newMessage,this->p);
    bn_mul(newRandomKey,this->randomKey,other);
    bn_mod(newRandomKey,newRandomKey,this->p);
    ep_new(newCommitment);
    ep_mul(newCommitment,this->commitment,other);
    return Pedersen_Commitment(newMessage,newRandomKey,newCommitment);
}

void Pedersen_Commitment::get_message(bn_t m)
{
    bn_copy(m,this->message);
}

void Pedersen_Commitment::get_randomKey(bn_t r)
{
    bn_copy(r,this->randomKey);
}

void Pedersen_Commitment::get_commitment(ep_t commitment)
{
    ep_copy(commitment,this->commitment);
}
