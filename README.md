# Linus

This respository serves as supplementary resources to follow along my [blog posts]() about developing Linux rootkits.

> [!WARNING]
> **Disclaimer:** This is intended for **educational** and **research** purposes only. Using this for any malicious activity is strictly prohibited. I (the author) am not responsible for any misuse, damage, or harm caused by this respository and its code.

## How to Use

I developed the module in the following order:

1. Baby Module
2. Priv Esc
3. File & Process Hiding
4. Network Hiding

So I recommend you work in that order as well if you're new to LKMs. 

## Environment

I developed/tested this on Ubuntu 22.04 (5.15.0-160), but the code should work for relatively modern kernels (6+)

## Credits

Largely inspired by [xcellerator](https://github.com/xcellerator/linux_kernel_hacking) and their rootkit development blog.
* The `ftrace_helper.h` is mostly the same from xcellerator's but ported to support newer kernels.
