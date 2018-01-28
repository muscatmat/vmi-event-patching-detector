#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

void code(){
	printf("I am what I am!\n");
}

int main() {
	printf("Hello World!\n");
	FILE * fp;

   
	while(1){
		printf("This is a test!\n");
		//int filedesc = open("testfile.txt", O_WRONLY | O_APPEND);
		//close(filedesc);
		fp = fopen ("testfile.txt", "w+");
		fclose(fp);
		sleep(5);
	}
	exit(1);
	return 0;
}
