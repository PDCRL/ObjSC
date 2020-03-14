all:
	g++ -std=c++17 decBallotDefault.cpp  -o decDef  -lpthread -O3 -g
	g++ -std=c++17 decBallotSCV.cpp      -o decSCV  -lpthread -O3 -g
	g++ -std=c++17 forkBallotDefault.cpp -o forkDef -lpthread -O3 -g
	g++ -std=c++17 forkBallotSCV.cpp     -o forkSCV -lpthread -O3 -g

clean:
	rm -rf *o decDef forkDef decSCV forkSCV
