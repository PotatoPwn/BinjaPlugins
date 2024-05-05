# Pattern Nopper
Scans the Binary file with a pattern, and if the pattern is present, the instruction will be NOP

## WARNING 
The DLL will NOP any instructions which contains the patterns in PatternList.h

Ive implemented a basic instruction size comparison check but it kinda sucks so oh welp :/


## References
- [Rikodot's SigScan Plugin](https://github.com/rikodot/binja_native_sigscan)
- The Binary Ninja Team at slack helping me with multithreading