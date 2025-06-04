#include <iostream>
#include <new>

#define MEM_1MiB    ((size_t)1024 * (size_t)1024)
#define MEM_1GiB    ((size_t)MEM_1MiB * (size_t)1024)

#define MEMSIZE_GiB ((size_t)128)
#define MEMSIZE     ((size_t)MEM_1GiB * (size_t)MEMSIZE_GiB)

int main() {
    size_t memsize = (size_t)MEMSIZE;

    std::cout << "allocating " << MEMSIZE_GiB << " GiB" << std::endl;

    try {
        char* buffer = new char[MEMSIZE];
    }
    catch (std::bad_alloc& e) {
        std::cerr << e.what() << std::endl;
        throw e;
    }

    std::cout << "allocated " << MEMSIZE_GiB << " GiB" << std::endl;

    return 0;
}
