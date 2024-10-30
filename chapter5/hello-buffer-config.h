#ifndef HELLO_BUFFER_CONFIG_H
#define HELLO_BUFFER_CONFIG_H

struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[12];
   char path[16];
};

#endif
