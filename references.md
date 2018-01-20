# History of Sice Channel Attacks

## Physical World Examples

* Crypto '99: [Differential Power Analysis](https://www.paulkocher.com/DifferentialPowerAnalysis.pdf)
* USENIX '09: [Compromising Electromagnetic Emanations of Wired Keyboards](https://lasec.epfl.ch/keyboard/), [demo](http://www.dailymotion.com/video/k7amb5qtOGW2C6Odmq)
* SIGGRAPH '14: [The Visual Microphone: Passive Recovery of Sound from Video](https://people.csail.mit.edu/mrub/VisualMic/), [demo](https://www.youtube.com/watch?v=FKXOucXB4a8)
* [System Bus Radio](https://github.com/fulldecent/system-bus-radio) [demo](https://www.youtube.com/watch?v=caGPmyMLYUI), based on USENIX '15 [GSMem: Data Exfiltration from Air-Gapped Computers over GSM Frequencies](https://www.usenix.org/node/190937)

## CPU Side Channels

### Timing Based

* CRYPTO '96: [Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems](https://www.paulkocher.com/TimingAttacks.pdf)
* USENIX '03: [Remote Timing Attacks are Practical](http://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf)

### Cache Based

* Colin Percival, BSDCan '05: [Cache Missing for Fun and Profit](http://www.daemonology.net/papers/cachemissing.pdf)
* Osvik, Shamir, Tromer, RSA '06: [Cache Attacks and Countermeasures: the Case of AES](https://eprint.iacr.org/2005/271.pdf)
* Yarom, Falkner, USENIX '14: [FLUSH + RELOAD: a High Resolution, Low Noise, L3 Cache Side-Channel Attack](https://eprint.iacr.org/2013/448.pdf)

## Spectre and Meltdown References

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