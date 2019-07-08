CXX=g++
CXXFLAGS=-Isrc/includes -O3 -march=native -pthread -lntl -lgmpxx -lgmp -lrelic 

ALL: test_security_param test_vec_length
	
test_security_param: ThisWork.o HenryOG11.o GrothK15.o pedersen.o utils.o ./src/test_security_param.cpp
	$(CXX)  ThisWork.o HenryOG11.o GrothK15.o pedersen.o utils.o ./src/test_security_param.cpp $(CXXFLAGS) -o test_security_param.out

test_vec_length: ThisWork.o HenryOG11.o GrothK15.o pedersen.o utils.o ./src/test_vec_length.cpp
	$(CXX)   ThisWork.o HenryOG11.o GrothK15.o pedersen.o utils.o ./src/test_vec_length.cpp $(CXXFLAGS) -o test_vec_length.out

pedersen.o: ./src/pedersen.cpp
	$(CXX) $(CXXFLAGS) -c ./src/pedersen.cpp -o pedersen.o

HenryOG11.o: ./src/HenryOG11.cpp
	$(CXX) $(CXXFLAGS) -c ./src/HenryOG11.cpp -o HenryOG11.o

ThisWork.o: ./src/ThisWork.cpp
	$(CXX) $(CXXFLAGS) -c ./src/ThisWork.cpp -o ThisWork.o

GrothK15.o: ./src/GrothK15.cpp
	$(CXX) $(CXXFLAGS) -c ./src/GrothK15.cpp -o GrothK15.o

utils.o: ./src/utils.cpp
	$(CXX) $(CXXFLAGS) -c ./src/utils.cpp -o utils.o

clean:
	rm -f *.o *.out
