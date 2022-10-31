struct message_data {
   int pid;
   int uid;
   int counter;
   char command[16];
   char message[12];
};

struct msg_t {
   // int unused_value;
   char message[12];
};
