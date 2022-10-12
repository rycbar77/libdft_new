# file_taint_libdft
Port libdft to windows and do dynamic taint analysis

The global injection method comes from [here](https://m417z.com/Implementing-Global-Injection-and-Hooking-in-Windows/)

DONE:

- [x] Port libdft to windows
- [x] Hook readfile and writefile to mark taint
- [x] Information leak alert
- [x] Get propogation chains
- [x] Visualize the chains
- [x] Global Injection to automatically track file

OPTIMIZATION:

- [ ] Blacklist(especially GUI apis)
- [ ] Record and replay to speed up after the first run
