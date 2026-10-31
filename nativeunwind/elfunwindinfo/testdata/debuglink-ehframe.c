/* Functions with .eh_frame unwind info. Built at -O0 so that each function
 * has a frame setup with several stack deltas, which keeps their basic blocks
 * from being merged. */
extern int sink(int);

#define F(n) int eh_func##n(int x) { return sink(x + n) + n; }

F(0) F(1) F(2) F(3) F(4) F(5) F(6) F(7) F(8) F(9) F(10) F(11)
