// Functions with known names for the native symbolizer tests.
void func_alpha(void) {}
void func_beta(void) {}
int func_gamma(int x) { return x + 1; }
int main(void) { func_alpha(); func_beta(); return func_gamma(0); }
