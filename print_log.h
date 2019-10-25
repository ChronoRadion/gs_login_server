unsigned short   port;
int              log_on        = 0;


void LogMessage (char * txt) {
    /* write log file */
        int MAXLOGSIZE = 512000;
        char LogPath[256] = ".\\logs\\";
        FILE *file;
        char file_name[256],
             new_file_name[256],
             base_file_name[256];
        char buffer [1024];
        time_t rawtime;
        struct tm * timeinfo;

 mkdir(LogPath);
        time ( &rawtime );
        timeinfo = localtime ( &rawtime );

        sprintf(base_file_name,"%s_[%d]", "gs_srv_em", port);

        sprintf(file_name, "%s_%s%s", LogPath, base_file_name, ".log");
        file = fopen( file_name, "a" );

         fseek(file, 0L, SEEK_END);
         if (ftell(file) > MAXLOGSIZE) {
             sprintf(new_file_name, "%s%s_%d%02d%02d_%02d%02d%02d%s", LogPath, base_file_name,timeinfo->tm_year+1900, timeinfo->tm_mon+1, timeinfo->tm_mday,
                                                        timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, ".bck");
             fclose( file );
             rename (file_name, new_file_name);
             file = fopen( file_name, "a" );
         }

        for (;;) {
            if ( (txt[strlen(txt)-1] == 0x0a) || (txt[strlen(txt)-1] == 0x0d) ) {
                txt[strlen(txt)-1] = 0x00;
            } else {
                break;
            }
        }

        sprintf(buffer, "\n%02d:%02d:%02d  %s",timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, txt);
        fputs( buffer, file );

//        fputs( txt, file );
//        fputs( "\n", file );

        fclose( file );
}

void my_printf (const char *f, ...) {
    va_list ap1;
    char buffer[1024];


    va_start(ap1, f);
    vprintf(f, ap1);
    if  (log_on == 1) {
        vsprintf (buffer, f, ap1);
        LogMessage(buffer);
    }
    va_end(ap1);
}
