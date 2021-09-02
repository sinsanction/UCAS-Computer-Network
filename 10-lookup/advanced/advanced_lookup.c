#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "advanced_lookup.h"

//#define CHECK

int main(){
    char line[MAX_LEN_LINE];
    TreeNode *root = (TreeNode *)malloc(sizeof(TreeNode));
    RouteEntry entry;
    long long memory = 0;
    int total_entry_num = 0;
    FILE *fp = fopen("../forwarding-table.txt", "r");

    // build route tree
    Tree_Init(root);
    memory += sizeof(TreeNode);

    while (fgets(line, MAX_LEN_LINE, fp)) {
        Get_Route_Entry(line, &entry);
        Tree_Add_Entry(&entry, root, 1, 0x80000000, &memory);
        total_entry_num++;
    }
    Tree_Leaf_Pushing(root, -1);
    printf("Total Entry: %d\n", total_entry_num);
    printf("Total Memory: %lld B\n", memory);

    // read all data
    RouteEntry *data_entry = (RouteEntry *)malloc(total_entry_num * sizeof(RouteEntry));
    fseek(fp, 0, SEEK_SET);
    for (int i=0; i<total_entry_num; i++) {
        fgets(line, MAX_LEN_LINE, fp);
        Get_Route_Entry(line, &data_entry[i]);
    }

    //look up all data
    struct timeval start, end;
    double time_use = 0;
    #ifdef CHECK
    FILE *fp_out = fopen("lookup_result.txt", "w");
    #endif

    gettimeofday(&start, NULL); 
    for (int i=0; i<total_entry_num; i++) {
        Tree_Lookup(data_entry[i].ipv4, root);
        //Tree_Lookup(data_entry[i].ipv4, root, 1, 0x80000000);
        #ifdef CHECK
        int port = Tree_Lookup(data_entry[i].ipv4, root);
        char ipv4_str[20];
        int_to_ipv4(data_entry[i].ipv4, ipv4_str);
        fprintf(fp_out, "%s %d %d %d ", ipv4_str, data_entry[i].prefix_len, data_entry[i].port_id, port);
        if (port == data_entry[i].port_id)
            fprintf(fp_out, "true\n");
        else
            fprintf(fp_out, "false\n");
        #endif
    }
    gettimeofday(&end, NULL);
    time_use = (end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec);

    printf("Total Time: %.6lf us\n", time_use);
    printf("Time per lookup: %.6lf ns\n", time_use * 1000 / total_entry_num);

    fclose(fp);
    #ifdef CHECK
    fclose(fp_out);
    #endif
    free(data_entry);
    Tree_Destroy(root);
    return 0;
}

void Tree_Init(TreeNode *root){
    root->port_id = -1;
    root->left = NULL;
    root->right = NULL;
}

void Tree_Destroy(TreeNode *node_now){
    if (node_now->left)
        Tree_Destroy(node_now->left);
    if (node_now->right)
        Tree_Destroy(node_now->right);
    free(node_now);
}

void Tree_Add_Entry(RouteEntry *entry, TreeNode *node_now, int prefix_len, uint32 prefix_bit, long long *memory){
    TreeNode *node;

    if (prefix_len > entry->prefix_len) {
        return;
    }

    if ((entry->ipv4 & prefix_bit) == 0) {
        if (node_now->left == NULL) {
            node = (TreeNode *)malloc(sizeof(TreeNode));
            *memory += sizeof(TreeNode);
            node->port_id = (entry->prefix_len == prefix_len)? entry->port_id : -1;
            node->left = NULL;
            node->right = NULL;
            node_now->left = node;
        } 
        Tree_Add_Entry(entry, node_now->left, prefix_len + 1, prefix_bit >> 1, memory);
    }
    else {
        if (node_now->right == NULL) {
            node = (TreeNode *)malloc(sizeof(TreeNode));
            *memory += sizeof(TreeNode);
            node->port_id = (entry->prefix_len == prefix_len)? entry->port_id : -1;
            node->left = NULL;
            node->right = NULL;
            node_now->right = node;
        } 
        Tree_Add_Entry(entry, node_now->right, prefix_len + 1, prefix_bit >> 1, memory);
    }
}

int Tree_Lookup(int ipv4, TreeNode *root){
    TreeNode *node_now = root;
    uint32 prefix_bit = 0x80000000;
    int i, port;
    for (i = 1; i <= 32; i++) {
        if ((ipv4 & prefix_bit) == 0) {
            if (node_now->left == NULL) {
                return node_now->port_id;
            } 
            node_now = node_now->left;
        }
        else {
            if (node_now->right == NULL) {
                return node_now->port_id;
            } 
            node_now = node_now->right;
        }
        prefix_bit = prefix_bit >> 1;
    }

    // case: prefix_len == 32
    return node_now->port_id;
}
/*
int Tree_Lookup(int ipv4, TreeNode *node_now, int prefix_len, uint32 prefix_bit){

    if (prefix_len > 32) {
        return node_now->port_id;
    }

    if ((ipv4 & prefix_bit) == 0) {
        if (node_now->left == NULL)
            return node_now->port_id;
        else
            return Tree_Lookup(ipv4, node_now->left, prefix_len + 1, prefix_bit >> 1);
    }
    else {
        if (node_now->right == NULL)
            return node_now->port_id;
        else
            return Tree_Lookup(ipv4, node_now->right, prefix_len + 1, prefix_bit >> 1);
    }
}
*/
void Tree_Leaf_Pushing(TreeNode *node_now, int parent_port){
    // if it is a internal node, inherits the port from parent node
    if (node_now->port_id == -1) { 
        node_now->port_id = parent_port;
    }

    // push port to leaf node
    if (node_now->left) {
        Tree_Leaf_Pushing(node_now->left, node_now->port_id);
    }
    if (node_now->right) {
        Tree_Leaf_Pushing(node_now->right, node_now->port_id);
    }
}

void Get_Route_Entry(char *line, RouteEntry *entry){
    char *ipv4, *prefix, *port;

    ipv4 = strtok(line, " ");
    prefix = strtok(NULL, " ");
    port = strtok(NULL, " ");
    entry->ipv4 = ipv4_to_int(ipv4);
    entry->prefix_len = atoi(prefix);
    entry->port_id = atoi(port);
}

uint32 ipv4_to_int(char *ipv4){
    uint32 sum = 0;
    for (int i=1; i<=4; i++) {
        sum = sum * 256 + atoi(ipv4);
        while (*ipv4 >= '0' && *ipv4 <= '9') ipv4++;
        ipv4++;
    }
    return sum;
}

void int_to_ipv4(uint32 ipv4, char *ipv4_str){
    char tmp[5];
    int ptr = 0;

    for (int i=3; i>=0; i--) {
        unsigned char c = *((unsigned char *)(&ipv4) + i);
        //itoa(c, tmp, 10);
        sprintf(tmp, "%d", c);
        strcpy(&ipv4_str[ptr], tmp);
        ptr += strlen(tmp);
        ipv4_str[ptr] = (i > 0) ? '.' : '\0';
        ptr++;
    }
}
