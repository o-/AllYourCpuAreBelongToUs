### Side channels   (10')

* maybe for motivation a physical example? (k)
* Timing based (k)
* The Cache hierarchy (k)
* cache based. flush+reload (k)
* (covert channels (k))

### Microarchitecture Attacks (15')

* Out of order execution (o)
* Speculative execution (o)
* Architectural state vs. Microarchitectural state (o)
* Covert channel with transient instruction as sender (diagram) (b)
* First example (b)

### Meltdown  (5')

* The attack (b)
* Fixes: KAISER, cpuid (b)
** (only mention briefly, since this is (a) solved problem and (b) not relevant for JITs)

### Spectre (10')

* Difference to Meltdown (b)
* Attack models (o)
* V1 (branch predictor) (o)
* V2 (BTB) (o)

### Spectre Mitigation (15')

* Band aids: Index Masking, Retpoline, Degrading Timer (o)
* Broader attack model? (b)

### Discussion (5')
