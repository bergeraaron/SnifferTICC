#include "log.h"

FILE * pFile;

void open_log()
{
    pFile = fopen("debug.log","w");
}

void write_to_log(char * string)
{
    if(pFile != NULL)
        fprintf(pFile,"%s\n",string);
}

void close_log()
{
    if(pFile != NULL)
        fclose(pFile);
}

