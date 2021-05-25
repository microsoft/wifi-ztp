### Type
- [ ] Bug fix
- [ ] Feature addition
- [ ] Feature update
- [ ] Breaking change

### Goals
Describe what the PR intends to achieve. If the change is a new feature, describe what it is. If the change is a bug fix, reference the issue being fixed. Provide any additional context and motiviation for making the change. Eg.
> Simplify maintenance of the event loop. A well-known open source library can be used in place of the custom written code, making it easier to use, understand, and debug.

### Technical Details
Describe how the goals of the PR were achieved. Eg.
> Replace custom event loop code with libevent.

### Test Results
Describe which tests were carried out and a summary of their results. Eg.
> Verified DPP exchange completed successfully with the following configurations:
> - [X] enrollee using ztpd, configurator using hostapd
> - [X] enrollee using ztpd, configurator using ArubaOS

### Reviewer Focus
Describe what reviewers should focus on. Eg.

> As the event loop mechanism is critical to the daemon, the use of a new library could introduce subtle corner cases that might not be easily exposed in tests. Please pay careful attention to whether the behavior of existing event loop uses could have changed.

### Future Work
Describe any future work that is required as a result of this change. Eg.
> * Long-running stress testing needs to be completed.
> * The old event loop code needs to be removed once stress-testing with libevent has been completed.

### Checklist
- [ ] Build target `all` compiles cleanly.
- [ ] cppcheck produces no output.
- [ ] clang-format delta produced no new output.
- [ ] Newly added functions include doxygen-style comment block.
