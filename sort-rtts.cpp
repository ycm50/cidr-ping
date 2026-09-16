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



// 从 CSV 第 4 列取出延迟（毫秒）。
//   "12.34"                       -> 12.34
//   "WG握手响应(0x02)@215.45"      -> 215.45
//   "连接失败" / "UDP无响应" / ""   -> 解析失败，该行跳过
// 老版本直接对整列调 stof()，遇到任何一个失败行都会抛 std::invalid_argument 退出，
// 于是「有失败记录就排不了序」——这里改成跳过并计数。
static bool parse_rtt(const std::string &field, float *out) {
    size_t at = field.rfind('@');
    std::string num = (at == std::string::npos) ? field : field.substr(at + 1);
    try {
        size_t used = 0;
        float v = std::stof(num, &used);
        if (used == 0) return false;
        *out = v;
        return true;
    } catch (...) {
        return false;
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
    getline(rtts, line); // 跳过表头
    int skipped = 0;
    while(getline(rtts, line)){
        if (line.empty()) continue;

        string ip = line.substr(0, line.find(","));
        float rtt = 0.0f;
        size_t last = line.rfind(",");
        string field = (last == string::npos) ? string() : line.substr(last + 1);
        if (!parse_rtt(field, &rtt)) {
            ++skipped;
            continue;
        }
        pairs.push_back({ip, rtt});
    }
    sort(pairs.begin(),pairs.end(),sort_rtts::smaller);
    rtts.close();
    rtts.open("rtts_sorted.csv",ios::out);
    for(auto pair:pairs){
        rtts<<pair.ip<<","<<pair.rtt<<"\n";
    }
    rtts.close();
    cout << "已排序 " << pairs.size() << " 行";
    if (skipped > 0) cout << "，跳过 " << skipped << " 行无法解析延迟的记录";
    cout << " -> rtts_sorted.csv" << endl;
    return 0;
}
