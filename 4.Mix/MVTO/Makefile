all:
	g++ -std=c++17 decMixDefault.cpp  -o decDef  -lpthread -O3 -g
	g++ -std=c++17 decMixSCV.cpp      -o decSCV  -lpthread -O3 -g
	g++ -std=c++17 forkMixDefault.cpp -o forkDef -lpthread -O3 -g
	g++ -std=c++17 forkMixSCV.cpp     -o forkSCV -lpthread -O3 -g

clean:
	rm -rf *o decDef forkDef decSCV forkSCV
