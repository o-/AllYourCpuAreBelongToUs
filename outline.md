### Side channels   (10')

* maybe for motivation a physical example?
* Timing based
* The Cache hierarchy
* cache based. flush+reload
* covert channels

### Microarchitecture Attacks (15')

* Out of order execution
* Speculative execution
* Architectural state vs. Microarchitectural state
* Covert channel with transient instruction as sender

### Meltdown  (5')

* The attack
* Fixes: KAISER, cpuid (only mention briefly, since this is
    (a) solved problem and (b) not relevant for JITs)

### Spectre (10')

* Difference to Meltdown
* Attack models
* V1 (branch predictor)
* V2 (BTB)

### Spectre Mitigation (15')

* Band aids: Index Masking, Retpoline, Degrading Timer
* Long-Term Mitigation

### Discussion (5')
