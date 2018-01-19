# History of Side Channel Attacks

## Physical World Examples

* Crypto '99: [Differential Power Analysis](https://www.paulkocher.com/DifferentialPowerAnalysis.pdf)
* USENIX '09: [Compromising Electromagnetic Emanations of Wired Keyboards](https://lasec.epfl.ch/keyboard/) [demo](http://www.dailymotion.com/video/k7amb5qtOGW2C6Odmq)
* SIGGRAPH '14: [The Visual Microphone: Passive Recovery of Sound from Video](https://people.csail.mit.edu/mrub/VisualMic/) [demo](https://www.youtube.com/watch?v=FKXOucXB4a8)
* [System Bus Radio](https://github.com/fulldecent/system-bus-radio) [demo](https://www.youtube.com/watch?v=caGPmyMLYUI), based on USENIX '15 [GSMem: Data Exfiltration from Air-Gapped Computers over GSM Frequencies](https://www.usenix.org/node/190937)

## CPU Side Channels

### Timing Based

When programs operate on secret data, a hostile process on the same CPU has many possibilities to observe it. It can measure timings, core utilization, memory access patterns, etc.

* CRYPTO '96: [Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems](https://www.paulkocher.com/TimingAttacks.pdf)
* USENIX '03: [Remote Timing Attacks are Practical](http://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf)

Example

```
static const char* secret = "the password"

bool check_pass(const char* input) {
  for (int i = 0; i < strlen(secret); ++i)
    if (secret[i] != input[i])
      return false;
  }
  return true;
}

```

This example is [not made up](https://rdist.root.org/2009/05/28/timing-attack-in-google-keyczar-library/).

Mitigation: Don't branch on secret values. (On Intel: use CMOV).

### Cache Based

```
static uint8_t secret = 42;

int not_telling_you_anything(int* guesses) {
    int pick = guesses[secret];
    return pick & 0;
}
```

* Colin Percival, BSDCan '05: [Cache Missing for Fun and Profit](http://www.daemonology.net/papers/cachemissing.pdf)
* Osvik, Shamir, Tromer, RSA '06: [Cache Attacks and Countermeasures: the Case of AES](https://eprint.iacr.org/2005/271.pdf)
* Yarom, Falkner, USENIX '14: [FLUSH + RELOAD: a High Resolution, Low Noise, L3 Cache Side-Channel Attack](https://eprint.iacr.org/2013/448.pdf)

# Spectre/Meltdown

## Speculative Execution

```
if (*x == 0) {
  *y = 1
}
...
```

CPU stalled to load `x` for several 100 cycles. Branch predictor says, branch took the then-branch in the past. Solution: follow predicted branch and execute "transiently". If the branch turns out to be mispredicted, throw away transient results. For example `*y = 1` has to be removed from the store buffer.

Problem: The transient instructions *are* executed. While at the architectural level their effects are reverted, we can observe their execution via side channels.

                  -   speculation   -
                /                     \
              /                         \
    transient    -| side channel |->     actual

(graph from J. Horn, RealWorldCrypto '18)

## Rough classification

* Meltdown: Speculative memory loads allow execution of transient instructions *after* a segv.
* Spectre 1: Branch predictor allows transient execution of the wrong branch.
* Spectre 2: Poisoning the Branch Target Buffer allows transient execution of (more or less) arbitrary code.

### Meltdown

Only affects Intel CPUs.

[Virtual memory](http://www.plantation-productions.com/Webster/www.artofasm.com/Linux/HTML/MemoryArchitecturea3.html) is organized in pages. A page is a continuous region of virtual address space and can be backed by physical memory. Page information is stored in the OS in a tree like structure, called page table tree.
A page has ACL bits, for example it can be Readable, Writeable, Executable. Pages can also be protected, eg. only accessible to the OS or the sanbox implementation.

Normally every process in a system has it's own virtual memory. When switching between processes the OS loads a different page table to the Memory Management Unit (MMU). However the OS internal memory is traditionally mapped into the process address space, but marked protected. This is to avoid switching the page table (which is expensive) on syscalls.

Translating a virtual memory address to a physical one requires several steps and the loading of several page table entries from memory. For perfomance ther is a Translation Lookaside Buffer (TLB) that remembers recently used mappings. If the page table entry is evicted from memory, but the actual mapping is in the TLB, intel CPUs perform a speculative load, even though it is not possible to check the protection bits yet.

Example:

```
1: static int measure[255];
2: int* kernel_secret; // pointer into (unaccessible) kernel memory space
3: measure[*kernel_secret_pointer % 255];
```
Line 3 will generate a segv, since we try to access protected memory. But the load was speculatively performed. By measuring timings for loads from `measure` (in the signal handler) we can recover one byte of kernel memory.

* Affects: Kernels
* Mitigation: [Page Table Isolation](https://lwn.net/Articles/741878/)

### Meltdown v1: Bounds Check Bypass

Exploiting code gadgets in a target process, to execute mispredicted branches. Affects programs operating on untrusted programs or data.

* Affects: Programs branching on user input
* Examples: Kernel, JIT, Parser, De-/Serializer, ...
* Mitigation: Masking, Branchless code, Microcode update

### Meltdown v2: Branch Target Injection

Poison the branch predictor for indirect branches. Requires exact knowledge of the branch predictor on a particular architecture. Allows attacking context to seed the predictor such that in `(*f)()` the speculation for the value of `*f` is attacker controlled, thus allowing arbitrary transient code execution.

* Affects: Programs using indirect jumps
* Examples: Hypervisors, Interpreters using threaded code, Code generated by compilers using jump tables, ...
* Mitigation: Retpoline, Microcode update

### Meltdown vn

Probably more ways to trigger speculation exist and probably more side-channels to exfiltrate data too.

## References

### Papers

* [Meltdown](https://arxiv.org/abs/1801.01207)
* [Spectre](https://arxiv.org/abs/1801.01203)

Previous Work:

* [Jump Over ASLR: Attacking Branch Predictors to Bypass ASLR](http://www.cs.binghamton.edu/~dima/micro16.pdf)

### Posts

* [spectreattack.com](https://spectreattack.com/)
* Jann Horn, Project Zero, [Reading privileged memory with a side-channel](https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html)
* [Some thoughts on Spectre and Meltdown](http://www.daemonology.net/blog/2018-01-17-some-thoughts-on-spectre-and-meltdown.html) by Colin Percival
* [Spectre & Meltdown: tapping into the CPU's subconscious thoughts](https://ds9a.nl/articles/posts/spectre-meltdown/)

### Talks

* J. Horn (Project Zero), RealWorldCrypto '18: [Spectre and Meltdown: Data leaks during speculative execution](https://www.youtube.com/watch?v=AFWgIAgMtiA)

## Mitigation

* [Webkit](https://webkit.org/blog/8048/what-spectre-and-meltdown-mean-for-webkit/) array index masking and pointer poisoning.
* [Firefox](https://blog.mozilla.org/security/2018/01/03/mitigations-landing-new-class-timing-attack/) disable SharedArrayBuffer and lower timer precision.
* [Linux](http://kroah.com/log/blog/2018/01/19/meltdown-status-2/)
* "End users and systems administrators should check with their operating system vendors and system manufacturers, and apply any updates as soon as they are available" [intel](https://web.archive.org/web/20180119041316/https://www.intel.com/content/www/us/en/architecture-and-technology/facts-about-side-channel-analysis-and-intel-products.html)
* "The latest microcode_ctl and linux-firmware packages from Red Hat do not include resolutions to the CVE-2017-5715 (variant 2) exploit. Red Hat is no longer providing microcode to address Spectre, variant 2, due to instabilities introduced that are causing customer systems to not boot. [...] Customers are advised to contact their silicon vendor to get the latest microcode for their particular processor." [redhat](https://web.archive.org/web/20180119205832/https://access.redhat.com/solutions/3315431?sc_cid=701f2000000tsLNAAY&)
* Open Hardware?
