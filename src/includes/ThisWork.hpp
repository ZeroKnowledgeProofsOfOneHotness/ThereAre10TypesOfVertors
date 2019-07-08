/*
 *Date: 2019/06/28
 *Project: Proof Of Concept for: There are 10 Types of Vectors (and Polynomials)
 *File: ThisWork.hpp
 *  Contains Class and method declarations of data structures needed for (HV)ZKPoK for One-Hotness, using the new protocol using the evaluation of polynomails to prove knowledge of witnesses
 */

#ifndef __POLY_HPP__
#define __POLY_HPP__
#include<NTL/ZZ_p.h>
#include<NTL/vec_ZZ_p.h>
#include"utils.hpp"
#include"pedersen.hpp"

#include<vector>
#include<tuple>

#include<chrono>
using namespace std;
using namespace NTL;

/* Class: ZKP_Prover_Vector_ThisWork 
 *
 * This class uses the idea that if f(t)=t^j, and is the polynomial of the witnesses than is it is probably a one-hot vector
 * This is an iterface for using this protocol and designed to be run along side the verifier subject to this order
 *  1)set_t_challenge
 *  2)get_commitments
 *  3)set_challenge
 *  4)get_verification
 */
class ZKP_Prover_Vector_ThisWork{
    private:
        chrono::duration<double> creation_timer,set_t_timer,get_commit_timer,set_challenge_timer,get_verify_timer; //Timing code
        Pedersen &P; //Single understading of the context of g and h
        vector<Pedersen_Commitment> Commitments; //Vector that is to be proven to be one hot
        uint location,bitlength; 
        vec_ZZ_p d,a,r,s,t,epsilon,gamma,delta;
        ZZ_p challenge,t_challenge;
        //TODO -- Modify this to match the notation in the paper
        //ZZ_p challenge,t_challenge,rpt,a,b,c;
        //vec_ZZ_p r,alpha,beta,gamma,delta,epsilon;
        //vector<ZZ_p> b_minus_a_inv,a_message,d_message;

    public:
        /* Method: Constructor
         *
         * Creates object with the initial conditions
         * 
         * Pedersen P: Holds to context of g, and h
         * vector<Pedersen_Commitment> Commitments: This will be proven to be a one-hot vector.
         * unit location: the location of the 1 in the witnesses
         */
        ZKP_Prover_Vector_ThisWork(Pedersen &P, vector<Pedersen_Commitment> Commitments, uint location);

        /*Method: Deconstructor
         *
         * Frees memory that is used by this object
         */
        ~ZKP_Prover_Vector_ThisWork();

        /* Method: set_t_challenge
         *
         * This is the setter for the random t, that is used to evaluate the polynomial at.
         * 
         * ZZ_p t_challenge: a random value provided by the verifier.
         */
        void set_t_challenge(ZZ_p t_challenge);

        /* Method: get_commitments
         *
         * This creates all the commitments need for the verification of this vector 
         * 
         * Returns: the commitments
         */
        tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>> get_commitments();

        /* Method: set_challenge
         *
         * ZZ_p challenge: the value used to constuct the verification equations
         */
        void set_challenge(ZZ_p challenge);

        /* Method: get_verification
         *
         * This will constuct the verification equations for the verifier
         */
        tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>> get_verification();

        /* Method: get_timers
         *
         * timeing code
         */
        tuple<chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>> get_timers();




};

/* Class: ZKP_Verifier_Vector_ThisWork 
 *
 * This class uses the idea that if f(t)=t^j, and is the polynomial of the witnesses than is it is probably a one-hot vector
 * This is an iterface for using this protocol and designed to be run along side the verifier subject to this order
 *  1)get_t_challenge
 *  2)set_commitments
 *  3)get_challenge
 *  4)set_verification
 *  5)accept
 */
class ZKP_Verifier_Vector_ThisWork{
    private:
        chrono::duration<double> creation_timer,set_commit_timer,set_verify_timer,accept_timer; //Timing code
        Pedersen &P;//Universal constext of g and h
        vector<ZZ_p> v,u,w,z; // verification arrary
        vector<Pedersen_Commitment> Commitments; //Vector to be verified opens to a one hot vector
        tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>> proof; //Initial commitments
        ZZ_p t_challenge,challenge;//Challenges
        uint bitlength,lambda;//Security paramater
        Pedersen_Commitment poly_commit;//result of the dot product
    public:
        /* Method: constructor
         *
         * Creates the object with initial conditions
         * 
         * Pedersen P: context of the elliptical curve generators g and h
         * vector<Pedersen_Commitments> Commitments: The array to be show is a one-hot vector
         * uint lambda: security parameter of this protocol
         */
        ZKP_Verifier_Vector_ThisWork(Pedersen &P, vector<Pedersen_Commitment> Commitments,uint lambda);

        /* Method: deconstructor
         *
         * Frees the memory that is used by this protocol
         */
        ~ZKP_Verifier_Vector_ThisWork();

        /* Method: get_t_challenge
         *
         * Returns: the random challenge used to evaluate the polynomial of commitments at.
         */
        ZZ_p get_t_challenge();

        /* Method: set_commitments
         *
         * Sets the initial commitments from the prover into memory to be verified in the accept stage later
         */
        void set_commitments(tuple<vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>,vector<Pedersen_Commitment>>);

        /* Method: get_challenge
         *
         * return: a random number for the prover to use to constuct the verification equations
         */
        ZZ_p get_challenge();
        
        /* Method: set_verification
         *
         * sets the verification equations, from the prover to memory to be verified in the accept stage later
         */
        void set_verification(tuple<vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>,vector<ZZ_p>>);

        /* Method: accept
         *
         * returns true if and only if commitments is a one-hot  vector and the prover knows the witnesses
         */
        bool accept();

        /* Method: get_timers 
         * timing code
         */
        tuple<chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>> get_timers();
};


#endif