#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "basic_lookup.h"

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
        Tree_Add_Entry(&entry, root, &memory);
        total_entry_num++;
    }
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
    root->net = 0;
    root->prefix_len = 0;
    root->port_id = -1;
    root->type = INTERNAL;
    root->left = NULL;
    root->right = NULL;
    root->parent = NULL;
}

void Tree_Destroy(TreeNode *node_now){
    if (node_now->left)
        Tree_Destroy(node_now->left);
    if (node_now->right)
        Tree_Destroy(node_now->right);
    free(node_now);
}

void Tree_Add_Entry(RouteEntry *entry, TreeNode *root, long long *memory){
    TreeNode *node_now = root;
    int mask = 0x80000000;
    uint32 prefix_bit = 0x80000000;

    int add_num = 0;
    for (int i = 1; i <= entry->prefix_len; i++) {
        if ((entry->ipv4 & prefix_bit) == 0) {
            if (node_now->left == NULL) {
                node_now->left = Tree_Add_Node(entry, i, mask, node_now);
                *memory += sizeof(TreeNode);
                add_num++;
            } 
            node_now = node_now->left;
        }
        else {
            if (node_now->right == NULL) {
                node_now->right = Tree_Add_Node(entry, i, mask, node_now);
                *memory += sizeof(TreeNode);
                add_num++;
            } 
            node_now = node_now->right;
        }
        mask = mask >> 1;
        prefix_bit = prefix_bit >> 1;
    }

    if (add_num == 0) {
        printf("network: %x same prefix, update: port %d -> port %d\n ", entry->ipv4 & mask, node_now->port_id, entry->port_id);
        node_now->port_id = entry->port_id;
    }
}

TreeNode *Tree_Add_Node(RouteEntry *entry, int prefix_len, int mask, TreeNode *parent) {
    TreeNode *node = (TreeNode *)malloc(sizeof(TreeNode));

    node->net = entry->ipv4 & mask;
    node->prefix_len = prefix_len;
    node->port_id = (entry->prefix_len == prefix_len)? entry->port_id : -1;
    node->type = (entry->prefix_len == prefix_len)? MATCH : INTERNAL;
    node->parent = parent;
    node->left = NULL;
    node->right = NULL;
    return node;
}

int Tree_Lookup(int ipv4, TreeNode *root){
    TreeNode *node_now = root;
    uint32 prefix_bit = 0x80000000;
    int i, port;
    for (i = 1; i <= 32; i++) {
        if ((ipv4 & prefix_bit) == 0) {
            if (node_now->left == NULL) {
                if (node_now->type == MATCH) {
                    return node_now->port_id;
                }
                else {
                    while (node_now->parent) {
                        if (node_now->parent->type == MATCH) {
                            return node_now->parent->port_id;
                        }
                        node_now = node_now->parent;
                    }
                    return -1;
                }
            } 
            node_now = node_now->left;
        }
        else {
            if (node_now->right == NULL) {
                if (node_now->type == MATCH) {
                    return node_now->port_id;
                }
                else {
                    while (node_now->parent) {
                        if (node_now->parent->type == MATCH) {
                            return node_now->parent->port_id;
                        }
                        node_now = node_now->parent;
                    }
                    return -1;
                }
            } 
            node_now = node_now->right;
        }
        prefix_bit = prefix_bit >> 1;
    }

    // case: prefix_len == 32
    if (node_now->type == MATCH) {
        return node_now->port_id;
    }
    else {
        printf("error: 1\n");
        return -1;
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
