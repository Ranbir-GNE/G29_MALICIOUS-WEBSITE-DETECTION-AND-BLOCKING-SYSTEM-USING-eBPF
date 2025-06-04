#include <iomanip>
#include <iostream>
#include <sstream>

using namespace std;

class Class
{
public:
    Class() : s2{ 0 } {
        cout << "Class constructed" << endl;
    }
    Class(const Class &c) : s2{ c.s2 } {
        cout << "Class constructed by cref" << endl;
    }
    union {
        struct {
            int a;
            int b;
        } s1;
    };
    union {
        struct {
            int a;
        } s2;
    };
};

int main() {
    Class c1;
    Class c2 = c1;
    cerr << left << setfill('.') << setw(10) << "[w10]"
         << setw(20) << "[w20]" << setw(0) << "[w0]" << endl;
    cerr << setw(20) << 100 << endl;

    return 0;
}
