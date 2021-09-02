#define MAX_LEN_LINE 30

typedef struct node {
    int port_id;
    struct node* left;
    struct node* right; 
} TreeNode;

typedef unsigned int uint32;

typedef struct {
    uint32 ipv4;
    int prefix_len;
    int port_id;
} RouteEntry;

void Tree_Init(TreeNode *root);
void Tree_Destroy(TreeNode *node_now);
void Tree_Add_Entry(RouteEntry *entry, TreeNode *node_now, int prefix_len, uint32 prefix_bit, long long *memory);
//int Tree_Lookup(int ipv4, TreeNode *node_now, int prefix_len, uint32 prefix_bit);
int Tree_Lookup(int ipv4, TreeNode *root);
void Tree_Leaf_Pushing(TreeNode *node_now, int parent_port);

void Get_Route_Entry(char *line, RouteEntry *entry);
uint32 ipv4_to_int(char *ipv4);
void int_to_ipv4(uint32 ipv4, char *ipv4_str);
