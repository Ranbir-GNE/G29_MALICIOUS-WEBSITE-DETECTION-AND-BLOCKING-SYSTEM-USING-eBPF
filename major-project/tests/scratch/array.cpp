#include <array>
#include <cctype>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <string>

using namespace std;

int main() {

    array<char, 12> buffer;

    auto print_size = [](const string &buffer) {
        cout << resetiosflags(cout.flags());
        cout << "size: " << buffer.size()
             << ", max_size: " << buffer.max_size()
             << ", sizeof: " << sizeof(buffer) << endl;
    };

    auto print_buffer = [](const string &buffer) {
        for (unsigned i = 0; i < buffer.size(); i++) {
            cout << resetiosflags(cout.flags());
            cout << "buffer[" << dec << i << "]: " << hex
                 << setw(2) << setfill('0') << setprecision(2)
                 << static_cast<unsigned>(buffer[i]) << ": "
                 << (isprint(buffer[i]) ? buffer[i] : '_') << endl;
            if (buffer[i] == '\0') break;
        }
    };

    print_size(string(buffer.begin()));
    cout << "empty: " << ((buffer.empty()) ? "yes" : "no") << endl;

    buffer.fill('\0');

    print_size(string(buffer.begin()));
    print_buffer(string(buffer.begin()));
    cout << "empty: " << ((buffer.empty()) ? "yes" : "no") << endl;

    snprintf(buffer.data(), buffer.size(), "hello, %s",
      "world");

    print_size(string(buffer.begin()));
    print_buffer(string(buffer.begin()));
    for (unsigned i = 0; i < buffer.size(); i++) {
        cout << resetiosflags(cout.flags());
        cout << "buffer[" << dec << i << "]: " << hex
             << setw(2) << setfill('0') << setprecision(2)
             << static_cast<unsigned>(buffer[i]) << ": "
             << (isprint(buffer[i]) ? buffer[i] : '_') << endl;
        if (buffer[i] == '\0') break;
    }
    cout << "empty: " << ((buffer.empty()) ? "yes" : "no") << endl;

    return 0;
}
