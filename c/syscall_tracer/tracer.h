#ifndef TRACER_H
#define TRACER_H

#define TASK_COM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
	int pid;
	char com[TASK_COM_LEN];
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long off;
};

#endif