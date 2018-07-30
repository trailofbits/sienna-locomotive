#ifndef Statz_HH
#define Statz_HH

#include <vector>

using namespace std;

namespace sl2 {
template <class T>
class Statz {

public:
    
    vector<T>   vals;

    double mean() const {
        double ret = 0;
        uint64_t n = vals.size();
        if(n==0) {
            return 0;
        }

        for( auto x : vals ) {
            ret += x;
        }

        return ret/n;
    };

    double stdev() const {
        auto n = vals.size();
        if( n==0 ) {
            return 0.0;
        }

        double avg = mean();
        double ret = 0;

        for( auto i=0; i<n; i++ ) {
            ret += ( (vals[i]-avg) * (vals[i]-avg) );
        }
        ret /= n;
        return sqrt(ret);
    };


    Statz& operator<<( vector<T> newvals ) {
        vals.append(newvals);
        return this;
    }

    Statz& operator<<( T val ) {
        vals.append(val);
        return this;
    };

    Statz& operator+( T val ) {
        return this<<val;
    };

};





}

#endif