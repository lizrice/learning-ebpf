struct message_data {
   int pid;
   int uid;
   int counter;
   char parent[16];
   char child[16];
   char message[12];
};

struct msg_t {
   // int unused_value;
   char message[12];
};
