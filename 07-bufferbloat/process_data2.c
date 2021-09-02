#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void Process_Data(char *file_in, char *file_out, char *data_name){
    FILE *fp_in, *fp_out;
    fp_in = fopen(file_in, "r");
    fp_out = fopen(file_out, "w");

    char s[1000];
    char *time, *data;
    double begin, now;
    int first = 1;
    while(fgets(s, 1000, fp_in)){
        data = strstr(s, data_name);
        time = &s[0];

        if(first){
            begin = atof(time);
            fprintf(fp_out, "%lf ", 0);
            first = 0;
        }
        else{
            now = atof(time);
            fprintf(fp_out, "%lf ", now - begin);
        }

        if(data){
            data += strlen(data_name);
            while(*data >= '0' && *data <= '9' || *data == '.'){
                fprintf(fp_out, "%c", *data);
                data++;
            }
            fprintf(fp_out, "\n");
        }
    }

    fclose(fp_in);
    fclose(fp_out);
}

int main(){
    Process_Data("taildrop/rtt.txt", "taildrop/rtt_out.txt", "time=");
    Process_Data("red/rtt.txt", "red/rtt_out.txt", "time=");
    Process_Data("codel/rtt.txt", "codel/rtt_out.txt", "time=");

    return 0;
}