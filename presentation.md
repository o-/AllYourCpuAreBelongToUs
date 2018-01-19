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

# Spectre/Meltdown

* [spectreattack.com](https://spectreattack.com/)
* Jann Horn, Project Zero, [Reading privileged memory with a side-channel](https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html)

## Speculative Execution

```
if (*x == 0) {
  *y = 1
}
...
```

CPU stalled to load `x` for several 100 cycles. Branch predictor says, branch took the then-branch in the past. Solution: follow predicted branch and execute "transiently". If the branch turns out to be mispredicted, throw away transient results. For example `*y = 1` has to be removed from the store buffer.

Problem: The transient instructions *are* executed. While at the architectural level their effects are reverted, we can observe their execution via side channels.

## Rough classification

* Meltdown: Speculative memory loads allow execution of transient instructions *after* a segv.
* Spectre 1: Branch predictor allows transient execution of the wrong branch.
* Spectre 2: Poisoning the Branch Target Buffer allows transient execution of (more or less) arbitrary code.

## Papers

* [Meltdown](https://arxiv.org/abs/1801.01207)
* [Spectre](https://arxiv.org/abs/1801.01203)

## Talks

* J. Horn (Project Zero), RealWorldCrypto '18: [Spectre and Meltdown: Data leaks during speculative execution](https://www.youtube.com/watch?v=AFWgIAgMtiA)

## Mitigation

* [Webkit](https://webkit.org/blog/8048/what-spectre-and-meltdown-mean-for-webkit/) array index masking and pointer poisoning.
* [Firefox](https://blog.mozilla.org/security/2018/01/03/mitigations-landing-new-class-timing-attack/) disable SharedArrayBuffer and lower timer precision.
