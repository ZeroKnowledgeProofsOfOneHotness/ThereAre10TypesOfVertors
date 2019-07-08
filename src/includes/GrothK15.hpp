/*
 *Date: 2019/06/28
 *Project: Proof Of Concept for: There are 10 Types of Vectors (and Polynomials)
 *File: GrothK15.hpp
 *  Contains Class and method declarations of data structures needed for (HV)ZKPoK for One-Hotness, using an efficient membership proof.
 */

#ifndef __MEMBERSHIP_HPP__
#define __MEMBERSHIP_HPP__
#include"utils.hpp"
#include<NTL/ZZ_p.h>
#include<NTL/ZZ_pX.h>
#include<vector>
#include<tuple>
#include<chrono>

using namespace NTL;
using namespace std;

/* Class: ZKP_Prover_1_TO_M
 * 
 * Prove that one of M commited values has an opening to 0, designed to be used in conjuction with Verifier
 */
class ZKP_Prover_1_TO_M{
    private:
        vector<Pedersen_Commitment> fn;
        vector<ZZ_p> rj,aj,sj,tj,pk,Commitments;
        vector<ZZ_pX> pi;
        Pedersen& P;
        Pedersen_Commitment C;
        int location,bitlength;
        ZZ_p challenge;

        
    public:
        ZKP_Prover_1_TO_M(Pedersen& P,Pedersen_Commitment C,vector<ZZ_p> Commitments,int loc);
        ~ZKP_Prover_1_TO_M();
        tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>> get_commitments();
        void set_challenge(ZZ_p challenge);
        tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,ZZ_p> get_verification();

};

/* Class: ZKP_Verifier_1_TO_M
 * 
 * Prove that one of M commited values has an opening to 0, designed to be used in conjuction with prover
 */
class ZKP_Verifier_1_TO_M{
    private:
        Pedersen& P;
        int bitlength;
        vector<Pedersen_Commitment> Commitments;
        tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>> Proof_Commitments;
        vector<ZZ_p> fj,Zaj,Zbj,values;
        ZZ_p challenge,Zd;
        Pedersen_Commitment Cd;


    public:
        ZKP_Verifier_1_TO_M(Pedersen& P,vector<Pedersen_Commitment> Commitments,vector<ZZ_p> values, Pedersen_Commitment Cd);
        ~ZKP_Verifier_1_TO_M();
        void set_commitments(tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>>);
        ZZ_p get_challenge();
        void set_verification(tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,ZZ_p>);
        bool accept();
};

/* class: ZKP_Prover_Membership
 *
 * An efficient communication cost protocol to prove set membership of the openings of a commited value, this is designed to be used in conjunction with the verifier of a similar name
 */
class ZKP_Prover_Membership{
    private:
        Pedersen& P;
        Pedersen_Commitment Commitment;
        vector<ZZ_p> values;
        int location;
        ZKP_Prover_1_TO_M *prover;
    public:
        ZKP_Prover_Membership(Pedersen& P,Pedersen_Commitment Commitment, vector<ZZ_p> values,int location);
        ~ZKP_Prover_Membership();
        tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>> get_commitments();
        void set_challenge(ZZ_p challenge);
        tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,ZZ_p> get_verification();


};

/* class: ZKP_Verifier_Membership
 *
 * An efficient communication cost protocol to prove set membership of the openings of a commited value, this is designed to be used in conjunction with the prover of a similar name
 */
class ZKP_Verifier_Membership{
    private:
        Pedersen& P;
        Pedersen_Commitment Commitment;
        vector<ZZ_p> values;
        ZKP_Verifier_1_TO_M *verifier;
    public:
        ZKP_Verifier_Membership(Pedersen& P,Pedersen_Commitment Commitment,vector<ZZ_p> values);
        ~ZKP_Verifier_Membership();
        void set_commitments(tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>>);
        ZZ_p get_challenge();
        void set_verification(tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,ZZ_p>);
        bool accept();
};

/* Class: ZKP_Prover_Vector_GrothK15
 *
 * This is an implemtation of an (HV)ZKPok system to prove knowledge of a vector opening to a one-hot vector
 * This was designed to be used in conjuction with the verifier of a similar name, subject to the order of execution
 *  1)set_vector_challenge
 *  2)get_commitments
 *  3)set_challenge
 *  4)get_verification
 */
class ZKP_Prover_Vector_GrothK15{
    private:
        chrono::duration<double> creation_timer,set_vector_challenge_timer,get_commit_timer,set_challenge_timer,get_verify_timer; //Timing code
        Pedersen& P;//Universal context of elliptic curve generators g and h
        vector<Pedersen_Commitment> Commitments; // vector of commitments, to be proven to open to a one hot vector
        int location; //Location of the 1 in the vector.
        vector<ZZ_p> arrChallenge;//array challenge to reduce to a membership proof
        ZKP_Prover_Membership *prover; //sub protocol of membership

    public:
        /* Method: Constructor
         * 
         * This initiates the prover with the inital conditions
         * 
         * Pedersen P: universol context of the pedersen commitment function
         * vector<Pedersen_Commitement> Commitments: the array to be proven
         * int location: the location of the 1 in the standard basis vector
         */
        ZKP_Prover_Vector_GrothK15(Pedersen& P,vector<Pedersen_Commitment> Commitments,int location);

        /* Method: Deconstructor
         * 
         * Cleans up object
         */
        ~ZKP_Prover_Vector_GrothK15();

        /* Method: set_vector_challenge
         * 
         * This comes from the verifier allowing them to select the set of elements the prover must prove membership of.
         * 
         * vector<ZZ_p> arrChallenge: vector of random numbers to be dot producted with the commitments vector.
         */
        void set_vector_challenge(vector<ZZ_p> arrChallenge);

        /* Method: get_commitments
         *
         * Returns: then commitments used by the verifier to prove set membership in arrChallenge
         */
        tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>> get_commitments();

        /* Method: set_challenge
         * 
         * ZZ_p challenge: random value that is choosen by the verifier to be used to constuct the verification  equations
         */        
        void set_challenge(ZZ_p challenge);

        /* Method: get_verification
         *
         * Returns: the verification equations to be used in verifires accept function.
         */
        tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,ZZ_p> get_verification();

        /* Method: get_timers
         *
         * Timing code
         */
        tuple<chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>> get_timers();

};

/* Class: ZKP_Verifier_Vector_GrothK15
 *
* This is an implemtation of an (HV)ZKPok system to prove knowledge of a vector opening to a one-hot vector
 * This was designed to be used in conjuction with the prover of a similar name, subject to the order of execution
 *  1)get_vector_challenge
 *  2)set_commitments
 *  3)get_challenge
 *  4)set_verification
 *  5)accept
 */
class ZKP_Verifier_Vector_GrothK15{
    private:
        chrono::duration<double> creation_timer,set_commit_timer,set_verify_timer,accept_timer;//timing code
        Pedersen& P;//universal understading of g and h
        vector<Pedersen_Commitment> Commitments; //Vector that will be proven to be a one hot vector
        vector<ZZ_p> arrChallenge;//array challenge, to be used to reduce the problem in to set membership
        ZKP_Verifier_Membership *verifier; // subprotocol that solves set membership
        uint lambda; //security parameter
    public:
        /* Method: constructor
         * 
         * creates the verifier with inital conditions,
         *  
         * Pedersen P: the context of the elliptic curve's generators g and h
         * vector<Pedersen_Commitment> Commitments: will be shown to be a one-hot vector
         * uint lambda: security parameter
         */
        ZKP_Verifier_Vector_GrothK15(Pedersen& P,vector<Pedersen_Commitment> Commitments,uint lambda);
        
        /* Method: Deconstructor
         *
         * Frees the object and it's working memory
         */
        ~ZKP_Verifier_Vector_GrothK15();

        /* Method: get_vector_challenge 
         * 
         * returns: array of random values to reduce the problem to set membership
         */
        vector<ZZ_p> get_vector_challenge();

        /*Method: set_commitments
         *
         * setter for the inital commitment that will be used in the verification step accopt
         */
        void set_commitments(tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>>);

        /* Method: get_challenge
         *
         * Returns: random integer, to be used to compute verification equations
         */
        ZZ_p get_challenge();

        /* Method: set_verification
         *
         * Get the verifications equations from the prover to be used in the verification step accept
         */
        void set_verification(tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,ZZ_p>);

        /* Method: accept
         *
         * Returns: true if and only if subprotol for membership returns true.
         */
        bool accept();
        tuple<chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>> get_timers();

};
#endif