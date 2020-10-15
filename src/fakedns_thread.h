/* Public interface to fakedns thread
*/

#ifndef fakedns_thread_h
#define fakedsn_thread_h

//Pthread start argument structure
typedef struct
{
	ushort port;
	char targetaddr[4];
} FDNSARGS;

//Thread Entry:
void* thread_fakedns(FDNSARGS* args);

#endif