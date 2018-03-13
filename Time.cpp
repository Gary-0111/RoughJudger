//
// Created by acm on 3/9/18.
//

#include "Time.h"

#include <stdlib.h>


void Time::getCurTime() {
    gettimeofday(&t, NULL);
}

Time Time::operator+(const Time &a) {
    Time r;
    r.t.tv_usec = this->t.tv_usec + a.t.tv_usec;
    r.t.tv_sec = this->t.tv_sec + a.t.tv_sec;
    if(r.t.tv_usec >= 1000000) {
        r.t.tv_usec -= 1000000;
        r.t.tv_sec += 1;
    }
    return r;
}

Time Time::operator-(const Time &a) {
    Time r;
    if(this->t.tv_usec < a.t.tv_usec) {
        r.t.tv_sec = this->t.tv_sec - a.t.tv_sec - 1;
        r.t.tv_usec = this->t.tv_usec - a.t.tv_usec + 1000000;
    } else {
        r.t.tv_sec = this->t.tv_sec - a.t.tv_sec;
        r.t.tv_usec = this->t.tv_usec - a.t.tv_usec;
    }
    return r;
}

Time::Time() {
    this->t.tv_sec = 0;
    this->t.tv_usec = 0;
}

std::ostream &operator<<(std::ostream &out, const Time &a) {
    out << a.t.tv_sec*1000 + a.t.tv_usec/1000 << "ms";
    return out;
}

Time::Time(timeval tv) {
    this->t.tv_sec = tv.tv_sec;
    this->t.tv_usec = tv.tv_usec;
}

bool Time::operator<(const Time &a) {
    if(this->t.tv_sec == a.t.tv_sec) return this->t.tv_usec < a.t.tv_usec;
    else return this->t.tv_sec < a.t.tv_sec;
}
