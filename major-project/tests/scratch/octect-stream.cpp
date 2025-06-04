#include <iomanip>
#include <iostream>
#include <sstream>

using namespace std;

int main() {
    size_t count = 0;

    string line;
    istringstream digest(
      "bd39d82cc1cb8b5d551833a24d77f06fad6ab263");
    while (digest.good()) {
        string octet;
        digest >> setw(2) >> octet;
        if (octet.size() == 2) {
            uint8_t byte = (uint8_t)stoul(octet, nullptr, 16);
            cout << "len: " << octet.size() << ", " << octet
                 << ", " << (int)byte << endl;
        }
    }

    cout << "count: " << count << endl;

    return 0;
}
