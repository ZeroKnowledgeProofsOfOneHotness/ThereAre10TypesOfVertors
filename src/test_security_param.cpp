/*
 *Date: 2019/07/02
 *Project: Proof Of Concept for: There are 10 Types of Vectors (and Polynomials)
 *File: test_security_param.cc
 *  Script to test the effect of the bit length of security param effects the running time of the algorithms
 */
#include"utils.hpp"

#include"ThisWork.hpp"
#include"HenryOG11.hpp"
#include"GrothK15.hpp"
#include<cmath>
#include<chrono>
#include<vector>

using namespace std;
using namespace NTL;

#define OK 0
#define FAIL 1
#define SIZE 16384
#define LOC 1
#define TRIALS 110
#define HENRYOG11
#define THISWORK
#define GROTHK15


int startup();
void gencurve();
void cleanup();

const char* const THISWORK_PROVER_TAGS[5]={"ThisWork_Prover_Creation","ThisWork_Prover_Set_t","ThisWork_Prover_Get_Commit","ThisWork_Prover_Set_Challenge","ThisWork_Prover_Get_Verify"};
const char* const THISWORK_VERIFIER_TAGS[4]={"ThisWork_Verifier_Creation","ThisWork_Verifier_Set_Commit","ThisWork_Verifier_Set_Verify","ThisWork_Verifier_Accept"};
const char* const GROTHK15_PROVER_TAGS[5]={"GrothK15_Prover_Creation","GrothK15_Prover_Set_t","GrothK15_Prover_Get_Commit","GrothK15_Prover_Set_Challenge","GrothK15_Prover_Get_Verify"};
const char* const GROTHK15_VERIFIER_TAGS[4]={"GrothK15_Verifier_Creation","GrothK15_Verifier_Set_Commit","GrothK15_Verifier_Set_Verify","GrothK15_Verifier_Accept"};
const char* const HENRYOG11_PROVER_TAGS[5]={"HenryOG11_Prover_Creation","HenryOG11_Prover_Set_t","HenryOG11_Prover_Get_Commit","HenryOG11_Prover_Set_Challenge","HenryOG11_Prover_Get_Verify"};
const char* const HENRYOG11_VERIFIER_TAGS[4]={"HenryOG11_Verifier_Creation","HenryOG11_Verifier_Set_Commit","HenryOG11_Verifier_Set_Verify","HenryOG11_Verifier_Accept"};
const uint SECURITY_PARAM_VALUES[9]={1,32,64,96,128,160,192,224,256};


int main(int argc, char** argv)
{
	if(startup() != OK)
	{
		return 0;
	}
	gencurve();
	Pedersen P;
	 //Create the commitments
    bn_t zero,one,p;
	ZZ prime;
    bn_new(zero);
    bn_new(one);
    bn_zero(zero);
    ep_curve_get_ord(p);
    conv(prime,p);
    ZZ_p::init(prime);
    bn_read_str(one,"1",1,10);
    vector<ZZ_p> values;
    ZZ_p shadow_one(1);

    vector<Pedersen_Commitment> Commitments;
    vector<ZZ_p> expon;
    for(int i=0;i<SIZE;i++)
    {
        bn_t temp;
        bn_new(temp);
        conv(temp,genRandom(256));;
        if(i==LOC)
        {
            Commitments.push_back(P.commit(one,temp));
        }else
        {
            Commitments.push_back(P.commit(zero,temp));
        };
    }

    cout<<"TAG"<<","<<"LAMBDA";
    for(int i=0;i<TRIALS;i++)
    {
        cout<<",TRIAL #"<<i;
    }

    cout<<endl;
    for(int iter=0;iter<9;iter++){
        uint security_param=SECURITY_PARAM_VALUES[iter];
        vector<tuple<chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>>> ThisWork_prover_timers,GrothK15_prover_timers,HenryOG11_prover_timers;
        vector<tuple<chrono::duration<double>,chrono::duration<double>,chrono::duration<double>,chrono::duration<double>>> ThisWork_verifier_timers,GrothK15_verifier_timers,HenryOG11_verifier_timers;
        for(int i=0;i<TRIALS;i++)
        {
            #if defined(THISWORK)
            {
                ZKP_Prover_Vector_ThisWork prover(P,Commitments,LOC);
                ZKP_Verifier_Vector_ThisWork verifier(P,Commitments,security_param);
                prover.set_t_challenge(verifier.get_t_challenge());
                verifier.set_commitments(prover.get_commitments());
                prover.set_challenge(verifier.get_challenge());
                verifier.set_verification(prover.get_verification());
                if(!verifier.accept())
                {
                    cout<<"FAILURE<ThisWork> Quitting program"<<endl;
                    return 0;
                }
                ThisWork_prover_timers.push_back(prover.get_timers());
                ThisWork_verifier_timers.push_back(verifier.get_timers());
            }
            #endif
            #if defined(GROTHK15)
            {
                ZKP_Prover_Vector_GrothK15 prover(P,Commitments,LOC);
                ZKP_Verifier_Vector_GrothK15 verifier(P,Commitments,security_param);
                prover.set_vector_challenge(verifier.get_vector_challenge());
                verifier.set_commitments(prover.get_commitments());
                prover.set_challenge(verifier.get_challenge());
                verifier.set_verification(prover.get_verification());
                if(!verifier.accept())
                {
                    cout<<"FAILURE<GrothK15> Quitting program"<<endl;
                    return 0;
                }
                GrothK15_prover_timers.push_back(prover.get_timers());
                GrothK15_verifier_timers.push_back(verifier.get_timers());
            }
            #endif
            #if defined(HENRYOG11)
            {
                ZKP_Prover_Vector_HenryOG11 prover(P,Commitments,LOC);
                ZKP_Verifier_Vector_HenryOG11 verifier(P,Commitments,security_param);
                prover.set_vector_challenge(verifier.get_vector_challenge());
                verifier.set_commitments(prover.get_commitments());
                prover.set_challenge(verifier.get_challenge());
                verifier.set_verification(prover.get_verification());
                if(!verifier.accept())
                {
                    cout<<"FAILURE<HenryOG11> Quitting program"<<endl;
                    return 0;
                }
                HenryOG11_prover_timers.push_back(prover.get_timers());
                HenryOG11_verifier_timers.push_back(verifier.get_timers());
            }
            #endif
        }

        for(int i=0; i<5;i++)
        {
            #if defined(THISWORK)
            cout<<THISWORK_PROVER_TAGS[i]<<","<<security_param;
            for(int j=0;j<TRIALS;j++)
            {
                chrono::duration<double> IDontLikeTuples[5]={get<0>(ThisWork_prover_timers[j]),get<1>(ThisWork_prover_timers[j]),get<2>(ThisWork_prover_timers[j]),get<3>(ThisWork_prover_timers[j]),get<4>(ThisWork_prover_timers[j])};
                cout<<","<<IDontLikeTuples[i].count();
            }
            cout<<endl;
            #endif
            #if defined(GROTHK15)
            cout<<GROTHK15_PROVER_TAGS[i]<<","<<security_param;
            for(int j=0;j<TRIALS;j++)
            {
                chrono::duration<double> IDontLikeTuples[5]={get<0>(GrothK15_prover_timers[j]),get<1>(GrothK15_prover_timers[j]),get<2>(GrothK15_prover_timers[j]),get<3>(GrothK15_prover_timers[j]),get<4>(GrothK15_prover_timers[j])};
                cout<<","<<IDontLikeTuples[i].count();
            }
            cout<<endl;
            #endif
            #if defined(HENRYOG11)
            cout<<HENRYOG11_PROVER_TAGS[i]<<","<<security_param;
            for(int j=0;j<TRIALS;j++)
            {
                chrono::duration<double> IDontLikeTuples[5]={get<0>(HenryOG11_prover_timers[j]),get<1>(HenryOG11_prover_timers[j]),get<2>(HenryOG11_prover_timers[j]),get<3>(HenryOG11_prover_timers[j]),get<4>(HenryOG11_prover_timers[j])};
                cout<<","<<IDontLikeTuples[i].count();
            }
            cout<<endl;
            #endif
        }

        for(int i=0; i<4;i++)
        {
            #if defined(THISWORK)
            cout<<THISWORK_VERIFIER_TAGS[i]<<","<<security_param;
            for(int j=0;j<TRIALS;j++)
            {
                chrono::duration<double> IDontLikeTuples[4]={get<0>(ThisWork_verifier_timers[j]),get<1>(ThisWork_verifier_timers[j]),get<2>(ThisWork_verifier_timers[j]),get<3>(ThisWork_verifier_timers[j])};
                cout<<","<<IDontLikeTuples[i].count();
            }
            cout<<endl;
            #endif
            #if defined(GROTHK15)
            cout<<GROTHK15_VERIFIER_TAGS[i]<<","<<security_param;
            for(int j=0;j<TRIALS;j++)
            {
                chrono::duration<double> IDontLikeTuples[4]={get<0>(GrothK15_verifier_timers[j]),get<1>(GrothK15_verifier_timers[j]),get<2>(GrothK15_verifier_timers[j]),get<3>(GrothK15_verifier_timers[j])};
                cout<<","<<IDontLikeTuples[i].count();
            }
            cout<<endl;
            #endif
            #if defined(HENRYOG11)
            cout<<HENRYOG11_VERIFIER_TAGS[i]<<","<<security_param;
            for(int j=0;j<TRIALS;j++)
            {
                chrono::duration<double> IDontLikeTuples[4]={get<0>(HenryOG11_verifier_timers[j]),get<1>(HenryOG11_verifier_timers[j]),get<2>(HenryOG11_verifier_timers[j]),get<3>(HenryOG11_verifier_timers[j])};
                cout<<","<<IDontLikeTuples[i].count();
            }
            cout<<endl;
            #endif
        }
    }
	P.~Pedersen();
	cleanup();
	return 0;
}

int startup()
{
	if(core_init() == RLC_OK)
	{
		return OK;
	}
	return FAIL;
}



void cleanup()
{
	core_clean();
}

void gencurve()
{
	ep_param_set_any_plain();
}


