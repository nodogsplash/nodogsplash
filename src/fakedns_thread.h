/* Public interface to fakedns thread
*/

#ifndef fakedns_thread_h
#define fakedsn_thread_h

//Pthread start argument structure
typedef struct
{
	int junk;	//This gets corrupted?
	int targetaddr[4];
	int port;
} FDNSARGS;

//Thread Entry:
void* thread_fakedns(void* args);

#endif