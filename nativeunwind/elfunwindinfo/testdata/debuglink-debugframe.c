/* A function with unwind info only in .debug_frame, which is moved to the
 * separate .gnu_debuglink file. */
extern int sink(int);

int debug_frame_only(int x)
{
	return sink(x) + 1;
}
