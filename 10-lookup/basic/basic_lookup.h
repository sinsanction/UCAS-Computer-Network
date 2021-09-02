#define MAX_LEN_LINE 30
#define INTERNAL 0
#define MATCH 1

typedef struct node {
    int net;
    int prefix_len;
    int port_id;
    int type;
    struct node* left;
    struct node* right; 
    struct node* parent;
} TreeNode;

typedef unsigned int uint32;

typedef struct {
    uint32 ipv4;
    int prefix_len;
    int port_id;
} RouteEntry;

void Tree_Init(TreeNode *root);
void Tree_Destroy(TreeNode *node_now);
void Tree_Add_Entry(RouteEntry *entry, TreeNode *root, long long *memory);
TreeNode *Tree_Add_Node(RouteEntry *entry, int prefix_len, int mask, TreeNode *parent);
int Tree_Lookup(int ipv4, TreeNode *root);

void Get_Route_Entry(char *line, RouteEntry *entry);
uint32 ipv4_to_int(char *ipv4);
void int_to_ipv4(uint32 ipv4, char *ipv4_str);
