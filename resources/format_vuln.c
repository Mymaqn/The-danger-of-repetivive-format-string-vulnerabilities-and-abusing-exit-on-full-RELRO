#include <stdio.h>
#include <unistd.h>

//gcc format_vuln.c -zrelro -znow -D_FORTIFY_SOURCE=2 -fstack-protector -o format_vuln

int main(void){
    int done = 0;
    char buf[0x20];

    while(done == 0){
        int choice = 0;
        printf("What would you like to do?\n");
        printf("1. Enter a format string\n");
        printf("2. Exit the loop\n");
        printf("> ");
        scanf("%d",&choice);

        if(choice == 1){
            printf("\nPlease enter your input:\n");
            read(0,buf,0x1f);
            printf(buf);
        }
        else{
            done = 1;
            break;
        }

    }

}