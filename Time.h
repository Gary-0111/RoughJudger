//
// Created by acm on 3/9/18.
//

#ifndef JUDGETEST_TIME_H
#define JUDGETEST_TIME_H

#include <sys/time.h>
#include <iostream>

class Time {
public:
    Time();
    Time(timeval tv);
    void getCurTime();
    bool operator < (const Time& a);
    Time operator + (const Time& a);
    Time operator - (const Time& a);
    friend std::ostream& operator << (std::ostream &out, const Time& a);
private:
    timeval t;
};


#endif //JUDGETEST_TIME_H
