#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
using namespace std;
namespace sort_rtts{
struct pair
{
    string ip;
    float rtt;
};
bool smaller(sort_rtts::pair a,sort_rtts::pair b){
    return a.rtt<b.rtt;
}
}



int main(){
   
    fstream rtts;
    rtts.open("rtts.csv", ios::in);
    if(!rtts){
        cout << "Failed to open rtts.csv" << endl;
        return 1;
    }
    vector<sort_rtts::pair> pairs;
    string line;
    getline(rtts, line);
    while(getline(rtts, line)){
        string ip = line.substr(0, line.find(","));
        float rtt = stof(line.substr(line.rfind(",") + 1));
        pairs.push_back({ip, rtt});
    }
    sort(pairs.begin(),pairs.end(),sort_rtts::smaller);
    rtts.close();
    rtts.open("rtts_sorted.csv",ios::out);
    for(auto pair:pairs){
        rtts<<pair.ip<<","<<pair.rtt<<"\n";
    }
    return 0;
}
