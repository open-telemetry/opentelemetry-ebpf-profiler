// Minimal C file used to produce a test ELF binary with known function symbols.
// Build: cc -o testbin test.c
void func_alpha(void) {}
void func_beta(void) {}
int func_gamma(int x) { return x + 1; }
int main(void) { func_alpha(); func_beta(); return func_gamma(0); }
