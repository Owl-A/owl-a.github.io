---
layout:     post
title:      Competitive coding tips 
date:       2017-12-13 16:02:00
summary:    Compilation of tips for competitive coding. Hope it helps! Stay algoed, pupper!  
categories: 
- Competitive coding 
thumbnail: file-code-o
tags:
- Tips
- C/C++
---
`Competitive coding` is a vast field, frankly even I'm a newbie to the world of competitive coding but I have noticed a few things that I wish I had known before. Just to prevent that regret among my fellow new coders on various online judges, I have compiled some of the facts in this article.
<br>
## speed of I/O in C++ 
Well, this is exclusively for C++ programmers and a disscussion on this may get a bit complicated. I've saved it for the appendix. But here are a few _thumb rules_ (if you want to think of them as 'rules') for speeding io in C++ on online judges, only.
Add these two lines in the beginning of the code just after the `int main(){`
```
ios_base::sync_with_stdio(false);
cin.tie(NULL);
```
These two lines essentially modify the internal workings of the `cout` and `cin` objects ( more in the appendix ). After adding these lines use *only* `cout` and `cin` for I/O and you might also want to use `cout << '\n'` in place of `cout << endl` for a little more speed up.
Or otherwise, if <strike> you are a true man </strike> you prefer using c-style I/O in C++ just remember including `#include <cstdio>` and don't bother adding the two lines I mentioned earlier. In fact `printf` and `scanf` are faster than `cin` and `cout`. Dont believe me? have a look yourself. Here are two submissions one with C-style I/O in C++  [32456606](http://codeforces.com/contest/876/submission/32456606) and the same one with C++-style (without the two lines) [32456606](http://codeforces.com/contest/876/submission/32456606) and C++ (with those two lines) [33210753](http://codeforces.com/contest/876/submission/33210753). And bang!
![you mad, bruh?](https://lh6.googleusercontent.com/Y-BBhbnvKsjsPnxu5puAu2OdeVMjU6R5xHKNutJSBf1zUy1NT9qUchswMx0I2neBlyvlWiPTsqodWa02Li4W=w1920-h900-rw)
The difference is Humongous! Okay?
<br>
##
