/* test buffer program */
#include <unistd.h>
#include <stdio.h>
#include <string.h>


/* gets -- Get string from stdin
char * gets ( char * str );

Reads characters from the standard input (stdin) and stores them as a C string into str until a newline character or the end-of-file is reached.

The newline character, if found, is not copied into str.

A terminating null character is automatically appended after the characters copied to str.

Notice that gets is quite different from fgets: 
not only gets uses stdin as source, 
but it does not include the ending newline character in the resulting string and 
does not allow to specify a maximum size for str (which can lead to buffer overflows).  */


/* puts -- Write string to stdout
int puts ( const char * str );

Writes the C string pointed by str to the standard output (stdout) and appends a newline character ('\n').

The function begins copying from the address specified (str) until 
it reaches the terminating null character ('\0'). This terminating null-character is not copied to the stream.

Notice that puts not only differs from fputs in that it uses stdout as destination, 
but it also appends a newline character at the end automatically (which fputs does not).  */
 
void Test()
{
   char buff[4];
   printf("Some input: ");
   gets(buff);
   puts(buff);
}
 
int main(int argc, char *argv[ ])
{
   Test();
   return 0;
}
