#include <unistd.h>

int main(int argc, char *argv[]) {
    // This process must not return (tests depend on it)
	return pause();
}
