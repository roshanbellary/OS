#ifndef STRESS_H_
#define STRESS_H_

void* u_hang(void*);
void* u_nohang(void*);
void* u_recur(void*);

// this one requires the fs to hold at least 5480 bytes for a file.
void* u_crash(void*);

#endif