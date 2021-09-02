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

void Process_Iperf(char *file_in, char *file_out){
    FILE *fp_in, *fp_out;
    fp_in = fopen(file_in, "r");
    fp_out = fopen(file_out, "w");

    char s[1000];
    char *time, *data;
    double now;

    while(fgets(s, 1000, fp_in)){
        time = strstr(s, "] ");
        data = strstr(s, "Bytes  ");
        if(time){
            time += 2;
            if(*time >= '0' && *time <= '9'){
                now = atof(time);
                fprintf(fp_out, "%lf ", now);
            }
        }
        if(data){
            data += 7;
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
    char file_in[50];
    char file_out[50];
    int maxq;
    scanf("%d", &maxq);

    sprintf(file_in, "qlen-%d/rtt.txt\0", maxq);
    sprintf(file_out, "qlen-%d/rtt_out.txt\0", maxq);
    Process_Data(file_in, file_out, "time=");

    sprintf(file_in, "qlen-%d/cwnd.txt\0", maxq);
    sprintf(file_out, "qlen-%d/cwnd_out.txt\0", maxq);
    Process_Data(file_in, file_out, "cwnd:");

    sprintf(file_in, "qlen-%d/qlen.txt\0", maxq);
    sprintf(file_out, "qlen-%d/qlen_out.txt\0", maxq);
    Process_Data(file_in, file_out, ", ");

    sprintf(file_in, "qlen-%d/iperf_result.txt\0", maxq);
    sprintf(file_out, "qlen-%d/iperf_result_out.txt\0", maxq);
    Process_Iperf(file_in, file_out);

    return 0;
}