# How to use it in C++

## Compilation

`ls -1 | grep .c | awk 'system("gcc -c "$1)'`

## Archiving into .a
`ar rcs libtommy.a *.o`

## verification
`ar t libtommy.a`

Note: you may remove the residual .o files after archiving.

## Usage 

#### in C

```c
#include "tommy.h"
```



#### in C++

```cpp
extern "C" {
    #include "tommy.h"
}

```

## Compilation

`gcc -o a.out main.c -L. -ltommy`

