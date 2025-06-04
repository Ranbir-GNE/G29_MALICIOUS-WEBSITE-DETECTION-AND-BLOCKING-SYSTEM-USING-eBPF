#include <cassert>

#include "enum.hpp"

using namespace std;

#define ndFlagBoolean(flags, bits) \
    ((flags & (bits)) == (bits))

enum class Items {
    ONE,
    TWO,
    THREE,

    MAX,
};

enum class Flags : uint16_t {
    NONE = 0,
    BIT_ONE = (1 << 0),
    BIT_TWO = (1 << 1),
    BIT_THREE = (1 << 2),

    ALL = (BIT_ONE | BIT_TWO | BIT_THREE)
};

enum class ndTPv3FanoutFlags : uint32_t {
    NONE = 0,
    DEFRAG = (1 << 0),
    ROLLOVER = (1 << 1),
};

int main() {
    ndFlags<Items> items;
    cout << "default init: items: " << items << endl;

    ndFlags<Flags> flags;
    cout << "default init: flags: " << flags << endl;

    flags |= Flags::BIT_ONE | Flags::BIT_TWO;
    cout << "BIT_ONE | BIT_TWO: flags: " << flags << endl;

    flags = Flags::BIT_THREE;
    cout << "assign BIT_THREE: flags: " << flags << endl;

    flags = (flags | Flags::BIT_ONE);
    cout << "flags | BIT_ONE: flags: " << flags << endl;

    ndFlags<Flags> more;
    more |= Flags::BIT_TWO | Flags::BIT_THREE;
    flags |= more;
    cout << "more BIT_TWO | BIT_THREE | flags: more: " << more << endl;

    ndFlags<Flags> all(Flags::ALL);
    cout << "all init: flags: " << all << endl;

    ndFlags<Flags> multiple(Flags::BIT_ONE | Flags::BIT_TWO);
    cout << "multiple init BIT_ONE | BIT_TWO: flags: " << multiple
         << endl;

    ndFlags<Flags> test(all);
    cout << "test init all: flags: " << test << endl;

    test = more | all;
    cout << "more | all: flags: " << test << endl;

    test &= ~Flags::BIT_ONE;
    cout << "more | all: flags: " << test << endl;

    ndFlags<ndTPv3FanoutFlags> fanout_flags(
      ndTPv3FanoutFlags::ROLLOVER);
    cout << "fanout_flags (32-bit): flags: " << fanout_flags << endl;

    return 0;
}
