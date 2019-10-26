/*
    Copyright 2005,2006,2007,2008,2009 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include "gs_login_proof.h"
#include "gspassenc.h"
//#include "print_log.h"



#ifdef WIN32
    #include <winsock.h>
    #include "winerr.h"

    #define close   closesocket
    #define sleep   Sleep
    #define MYRAND  (u_int)GetTickCount()
    #define ONESEC  1000
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <pthread.h>
    #include <sys/times.h>

    #define MYRAND  (u_int)times(0)
    #define ONESEC  1
    #define stricmp strcasecmp
    #define SOCKET_ERROR (-1)
#endif

#include <mysql.h>


#ifdef WIN32
    #define quick_thread(NAME, ARG) DWORD WINAPI NAME(ARG)
    #define thread_id   DWORD
#else
    #define quick_thread(NAME, ARG) void *NAME(ARG)
    #define thread_id   pthread_t
#endif

thread_id quick_threadx(void *func, void *data) {
    thread_id       tid;
#ifdef WIN32
    if(!CreateThread(NULL, 0, func, data, 0, &tid)) return(0);
#else
    pthread_attr_t  attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    //pthread_attr_setstacksize(&attr, 1<<18); //PTHREAD_STACK_MIN);
    if(pthread_create(&tid, &attr, func, data)) return(0);
#endif
    return(tid);
}



#define CPY(DST,SRC) mystrcpy(DST, SRC, sizeof(DST))
#define CMPCPY(x,y)  if(!strcmp(par, x)) CPY(y, vval);
#define CMPNUM(x,y)  if(!strcmp(par, x)) vtype = y;
#define LID          "1"






//void generate_pids(u_char *fname);
//int bind_job(u_short port);
int bind_job(u_short port, u_short soc_type, u_short protocol);

quick_thread(client, int sd);
quick_thread(client_udp, int sd);
int send_login(int sd, ...);
void gamespy3dxor(u_char *data, int len);
int recv_parval(int sd, u_char *par, int parsz, u_char *val, int valsz, int *gsoff);
int mystrcpy(u_char *dst, u_char *src, int max);
u_char *create_rand_string(u_int seed, u_char *data, int len, u_char *table);
u_short crc16(u_short crc, unsigned char *data, int len);
int timeout(int sock, int secs);
void std_err(void);



typedef struct {
    int     pid;
    u_char  *user;
} mypids_t;

int     sendlc1       = 1,
        verbose       = 0,
        udp_27900     = 0,
        gs_encoding   = 0,
//        log_on        = 0,
        extra_log     = 0;
u_char  *dbhost, 
        *dbname, 
        *dbuser,
        *dbpass,
        *default_nick,
        *default_pass;

MYSQL     *conn;
MYSQL_RES *res = NULL;
MYSQL_ROW row;
u_char    column_value[512] = "";
//u_short   port;

#ifdef WIN32
HANDLE hMutex = 0;
#else
pthread_mutex_t hMutex;
#endif

void mysql_close_connection (void) {
    if (res != NULL) {
        mysql_free_result(res);
        res = NULL;
    }
    mysql_close(conn);
}

int mysql_create_connection (void) {
 /*  create MySQL connection
  *  return -1 if connection is failed
  *  return 1 if version of MySQL >= 5.x
  *  return 0 if version of MySQL <  5.x*/

    conn = mysql_init(NULL);
    if(!conn) {
        my_printf("Failed to initate MySQL connection\n");
        return (-1);
    }
    if (!mysql_real_connect(conn, dbhost, dbuser, dbpass, dbname, 0, NULL, 0)) {
        my_printf("%s\n", mysql_error(conn));
        return (-1);
    }

    /*
     * major_ver * 10000 + minor_ver * 100 + sub_vesion
     * 5.0.12 = 50012
     */
    if (mysql_get_server_version(conn)>=50000) {
        return 1;
    }
    return 0;
}

int mysql_exec_query (char * query_txt) {
    /*
     * return 0 if query return 0 row
     * return 1 if query return >0 row
     */
    if (res != NULL) {
        mysql_free_result(res);
        res = NULL;
    }
if  (log_on == 1) {
    LogMessage(query_txt);
}
//LogMessage ("1");
    if (mysql_query (conn, query_txt)) {
        my_printf("%s\n", mysql_error(conn));
        return 0;
    }
//LogMessage ("2");
    if ((res = mysql_use_result (conn)) == NULL)
        return 0;
//LogMessage ("3");
    row = mysql_fetch_row (res);
//LogMessage ("4");
    if (row == NULL) {
        return 0;
    }
//LogMessage ("5");
    return 1;
}

u_char *mysql_field_value (int row_num) {
    /* return field value of row_num */
    sprintf(column_value,"%s", row[row_num]);
    return column_value;
}

int main(int argc, char *argv[]) {
    struct  sockaddr_in peer;
    int     sdl,
            sda_udp,
            sda,
            psz,
            i,
            version5,
            spid;
    //u_short port;
    char    query_txt[512];

#ifdef WIN32
    WSADATA    wsadata;
    WSAStartup(MAKEWORD(1,0), &wsadata);
#endif
    version5 = 0;
    port = 0;
    spid = 30000000;

    setbuf(stdout, NULL);

    fputs("\n"
          "GS login server emulator v.2.3\n"
          "by Luigi Auriemma\n"
          "e-mail: aluigi@autistici.org\n"
          "web:    aluigi.org\n\n"
          "Modified by Andrew Vasiliev (Ukraine 2010)\n"
          "e-mail: vasiliev1979@yandex.ru\n"
          "\n", stdout);

    if(argc < 2) {
        my_printf("\n"
            "Usage: %s [options]\n"
            "\n"
            "Options:\n"
            "-x port   port to listen connections\n"
            "          port can be 29900 (gpcm), 29901 (gpsp),\n"
            "          29920 (gamestats, XORed with \"GameSpy3D\")\n"
            "          or any other known port\n"
            "-v        verbose output\n"
            "-u        emulate 27900 UDP port\n"
            "-spid     start PID number for accounts (30000000 default).\n"
            "-l        1 - logfile on, 0 - logfile off (default). FOR DEBUG.\n"
            "-dbhost   host MySQL DB\n"
            "-dbname   DB name\n"
            "-dbuser   DB user\n"
            "-dbpass   DB password\n"
            "\n", argv[0]);
        exit(1);
    }

    argc--;
    for(i = 1; i < argc; i++) {
        int param_ok = 0;
        if ((argv[i][0] != '-') && (argv[i][0] != '/')) {
            my_printf("\nError: wrong argument (%s)\n", argv[i]);
            exit(1);
        }
		
        if(!strcmp("v", (char *) &argv[i][1]))      {verbose = 1;              param_ok=1;}
        if(!strcmp("u", (char *) &argv[i][1]))      {udp_27900 = 1;            param_ok=1;}
        if(!strcmp("x", (char *) &argv[i][1]))      {port = atoi(argv[++i]);   param_ok=1;}
        if(!strcmp("l", (char *) &argv[i][1]))      {log_on = atoi(argv[++i]); param_ok=1;}
//        if(!strcmp("z", (char *) &argv[i][1]))      {extra_log = 1;            param_ok=1;}
        
        if(!strcmp("spid", (char *) &argv[i][1]))   {spid = atoi(argv[++i]);   param_ok=1;}
        if(!strcmp("dbhost", (char *) &argv[i][1])) {dbhost = argv[++i];       param_ok=1;}
        if(!strcmp("dbname", (char *) &argv[i][1])) {dbname = argv[++i];       param_ok=1;}
        if(!strcmp("dbuser", (char *) &argv[i][1])) {dbuser = argv[++i];       param_ok=1;}
        if(!strcmp("dbpass", (char *) &argv[i][1])) {dbpass = argv[++i];       param_ok=1;}
        if (!param_ok) {
            my_printf("\nError: wrong command-line argument (%s)\n", argv[i]);
            exit(1);
        }
        param_ok = 0;
    }
     
    if (port==0) {
        my_printf("ERROR: port number not finded");
        exit(1);
    }

    version5 = mysql_create_connection ();
    if (version5 == -1) {
        my_printf("ERROR: failed connect to DB");
        exit(-1);
    }

    if(port == 29900) {
        if (version5) {
            sprintf (query_txt,"select * from information_schema.tables where table_name = 'player' and table_schema='%s' limit 0,1",dbname);
        } else {
            sprintf (query_txt,"SHOW TABLES LIKE 'player' ");
        }

        if (!mysql_exec_query (query_txt)) {
            LogMessage("Table 'player' not found. Create table...");
            mysql_exec_query("CREATE TABLE player (id int(8) unsigned NOT NULL, email varchar(255) NOT NULL, "
                       "password varchar(255) NOT NULL, passwordenc varchar(255) NOT NULL, nick varchar(255) NOT NULL, "
                       "PRIMARY KEY USING BTREE (id) )");
            sprintf (query_txt,"INSERT INTO player (id, email, password, passwordenc, nick) VALUES (%d, '' '','' '', '' '', '' '')",spid);
            mysql_exec_query(query_txt);
            LogMessage("Table 'player' created successfuly");
        }
/*
        if (version5) {
            sprintf (query_txt,"select * from information_schema.tables where table_name = 'gamespy_pass' and table_schema='%s' limit 0,1",dbname);
        } else {
            sprintf (query_txt,"SHOW TABLES LIKE 'gamespy_pass' ");
        }

        if (!mysql_exec_query (query_txt)) {
            LogMessage("Table 'gamespy_pass' not found. Create table...");
            mysql_exec_query("CREATE TABLE gamespy_pass (password varchar(255) NOT NULL, passwordenc varchar(255) NOT NULL, "
                             "PRIMARY KEY USING BTREE (passwordenc) )");
            mysql_exec_query(query_txt);
            LogMessage("Table 'gamespy_pass' created successfuly");
        }
 */
    }

    if (udp_27900) {
        sda_udp = bind_job(27900, SOCK_DGRAM, IPPROTO_UDP);
        my_printf("- wait connections on port %hu (UDP):\n", 27900);
        quick_threadx(client_udp, (void *)sda_udp);
    }
    
    if(port == 29920) {
        my_printf("- encoding activated\n");
        gs_encoding = 1;
    } 
    
    if(port == 29901) {
        my_printf("- disable the initial sending of \\lc\\1\n");
        sendlc1 = 0;
    }

    sdl = bind_job(port, SOCK_STREAM, IPPROTO_TCP);
    my_printf("- wait connections on port %hu:\n", port);
	
	mysql_close_connection ();	
		
#ifdef WIN32
    hMutex =CreateMutex(NULL, 0, NULL);
#else
    pthread_mutex_init (&hMutex, NULL);
#endif

    for(;;) {
        psz = sizeof(struct sockaddr_in);
        sda = accept(sdl, (struct sockaddr *)&peer, &psz);
        if(sda < 0) {
            my_printf("- accept() failed, continue within one second\n");
            close(sdl);
            sleep(ONESEC);
            sdl = bind_job(port, SOCK_STREAM, IPPROTO_TCP);
            continue;
        }

        my_printf("  %s:%hu\n", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));

        if(!quick_threadx(client, (void *)sda)) close(sda);
    }
    //mysql_close_connection();
#ifdef WIN32
    CloseHandle(hMutex);
    shutdown(sdl,SD_BOTH);
#else
    pthread_mutex_destroy(&hMutex);
    shutdown(sdl,SHUT_RDWR);
#endif
    close(sdl);
#ifdef WIN32
    WSACleanup ();
#endif
    return(0);
}



int bind_job(u_short port, u_short soc_type, u_short protocol) {
    struct  sockaddr_in peerx;
    int     sdl,
            on = 1;

    peerx.sin_addr.s_addr = INADDR_ANY;
    peerx.sin_port        = htons(port);
    peerx.sin_family      = AF_INET;

    sdl = socket(AF_INET, soc_type /*SOCK_STREAM*/, protocol /*IPPROTO_TCP*/);
    if(sdl < 0) std_err();
    if (protocol==IPPROTO_TCP)
        if(setsockopt(sdl, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) std_err();
    if(bind(sdl, (struct sockaddr *)&peerx, sizeof(struct sockaddr_in))   < 0) std_err();
    if (protocol==IPPROTO_TCP)
        listen(sdl, SOMAXCONN);
    return(sdl);
}

quick_thread(client_udp, int sd) {
    char buf[1024];
    int  fromlen,
         len;
    struct sockaddr_in from,
                       addr_to;

    for(;;) {
        timeout(sd, 0);
        fromlen = sizeof(struct sockaddr);
        len = recvfrom(sd, buf, 1024, 0, (struct sockaddr *) &from, &fromlen);
        buf[0]=' ';
        buf[1]=' ';
        buf[2]=' ';
        buf[3]=' ';
        buf[4]=' ';
        if (len == SOCKET_ERROR) std_err;
//if(verbose) my_printf("  client_udp '%s'\n", buf);
        if ((len == 18) && (!strcmp(buf , "     battlefield2")) && !(len == SOCKET_ERROR)) {
          buf[0]=0xfe;
          buf[1]=0xfd;
          buf[2]=0x09;
          buf[3]=0x00;
          buf[4]=0x00;
          buf[5]=0x00;
          buf[6]=0x00;
          addr_to.sin_family      = AF_INET;
          addr_to.sin_port        = from.sin_port;
          addr_to.sin_addr.s_addr = from.sin_addr.s_addr;

          len = sendto(sd, buf, 7, 0, (struct sockaddr *) &addr_to, sizeof(struct sockaddr));
          if (len == SOCKET_ERROR)  std_err;
        }
    }
}


char * escape_str (char *txt, char *esc_out) {

    *esc_out = 0x0;
    mysql_real_escape_string(conn, esc_out, txt, strlen(txt));

    return esc_out;
}

quick_thread(client, int sd) {
    int     i,
            ret,
            vtype,
            gsoff,
            error_code,
            max_id,
            mycrc            = 0;
    u_char  par[64]          = "",
            vval[1024]        = "",
            vmod[32]          = "",
            userid[32]       = "",
            profileid[32]    = "",
            xprofileid[32]   = "",
            sesskey[32]      = "",
            client_chall[64] = "",
            server_chall[11] = "",
            user[128]        = "",
            passenc[128]     = "",  // encripted password
            nick[128]        = "",
            email[128]       = "",
            uniquenick[128]  = "",
            password[128]    = "",  // password
            reason[1024]     = "",
            lt[25]           = "",
            id[32]           = "1",
            response[64]     = "";
    char    error_msg[512]   = "",
            error_code_string[20] = "",
            temp[1024]       = "",
            esc1 [1024]       = "",
            esc2 [1024]       = "",
            esc3 [1024]       = "";
//    u8      *pass_temp;

    sprintf(userid,    "%u", MYRAND);   // something pseudo-random, not important
    sprintf(profileid, "%u", MYRAND + 2);
    sprintf(sesskey,   "%u", MYRAND + 3);
    sprintf(vmod,      "%u", MYRAND + 4);

    create_rand_string(MYRAND, server_chall, sizeof(server_chall), "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    create_rand_string(MYRAND, lt, sizeof(lt), "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ][");
    strcpy(lt + 22, "__");

    /********************************************/
    /*** только для тестов                    ***/
    //strcpy(server_chall, "JIPGLMHACP");
    //strcpy(lt, "QZPJ5Bw2dGGNkl]YtSU0GE__");
    /********************************************/


    if(sendlc1) {
        if(send_login(sd,
            "lc",           "1",
            "challenge",    server_chall,
            "id",           id,
            NULL) < 0) goto give_up;
    }

    if(timeout(sd, 300)) goto give_up;
    for(;;) {
        if(verbose) my_printf("  %15s\n", "---");   // data block received

        gsoff = 0;
        vtype  = 0;
        for(;;) {
            ret = recv_parval(sd, par, sizeof(par), vval, sizeof(vval), &gsoff);
            if(ret < 0) goto give_up;
            if(ret == 1) break; // 1 = break now, 2 = break later

            if(verbose) my_printf("  %15s: %s\n", par, vval);

            if(!vtype) {
                     CMPNUM("newuser",      1)
                else CMPNUM("login",        2)
                else CMPNUM("logout",       3)
                else CMPNUM("search",       4)
                else CMPNUM("others",       5)
                else CMPNUM("pmatch",       6)
                else CMPNUM("nicks",        7)
                else CMPNUM("auth",         8)
                else CMPNUM("authp",        9)
                else CMPNUM("getpd",        10)
                else CMPNUM("setpd",        11)
                else CMPNUM("getprofile",   12)
                else CMPNUM("check",        13)
                else CMPNUM("addbuddy",     14)
                else CMPNUM("status",       15)
                else CMPNUM("authadd",      16)
                else vtype = -1;
                // "updatepro" doesn't need to be handled
            } else {
                     CMPCPY("userid",       userid)
                else CMPCPY("profileid",    profileid)
                else CMPCPY("email",        email)
                else CMPCPY("uniquenick",   uniquenick)
                else CMPCPY("user",         user)
                else CMPCPY("passenc",      passenc)
                else CMPCPY("passwordenc",  passenc)
                else CMPCPY("pass",         password)
                else CMPCPY("nick",         nick)
                else CMPCPY("challenge",    client_chall)
                else CMPCPY("id",           id)
                else CMPCPY("reason",       reason)
                else CMPCPY("newprofileid", xprofileid)
                else CMPCPY("response",     response)
                else CMPCPY("fromprofileid",xprofileid)
            }

            if(ret) break;  // in case of a "\final\" with remaining data (gs_encoding)
        }
        if (strlen(passenc) != 0) {
/* v1
            CPY(password, pass);
            pass_temp = base64_decode(password, &i);
            gspassenc(pass_temp);
            CPY(password, pass_temp);
            my_printf("  password=%p  pass_temp=%p\n", password, pass_temp);
            free(pass_temp);
 */

//            my_printf("starting decrypt pasword\n");
//            my_printf(" [before all]          password='%s'  passenc='%s'\n", password, passenc);
            CPY(password, passenc);
//            my_printf(" [after CPY]           password=%s\n", password);
            i = strlen (password);
            base64_decode(password, &i);
//            my_printf(" [after base64_decode] password=%s\n", password);
            gspassenc(password);
//            my_printf(" [after gspassenc]     password=%s\n", password);

        }
        if(verbose) my_printf("  %15s\n", "---");   // data block received

#ifdef WIN32
        WaitForSingleObject (hMutex, INFINITE);
#else
        pthread_mutex_lock(&hMutex);
#endif
        mysql_create_connection ();
		
        //nicks
        if (vtype == 7) {
/*
            sprintf(temp,"INSERT INTO gamespy_pass (passwordenc, password) VALUES ('%s', '%s')",pass, password);
            mysql_exec_query(temp);
 */
            sprintf(temp,"SELECT id, nick FROM player WHERE email='%s' AND passwordenc='%s' ",escape_str(email, esc1),passenc);
            if (!mysql_exec_query(temp)) {
                vtype = 18;
            } else {
                mystrcpy(nick,       mysql_field_value (1), sizeof (nick));
                mystrcpy(uniquenick, nick,                  sizeof (uniquenick));
                mycrc = atoi(mysql_field_value (0));
            }
        }

        //login
        if (vtype == 2) {
            sprintf (temp,"SELECT id, email, password, nick FROM player WHERE nick='%s' ",escape_str(uniquenick, esc1) );
            if (!mysql_exec_query(temp)) {
                //nick not finded in DB
                error_code = 260;
                mystrcpy(error_msg, "The nick not finded in Database.", sizeof(error_msg));
                vtype = 17;
            } else {
                //nick exist in DB
                mystrcpy(password,   mysql_field_value (2), sizeof (password));
                mystrcpy(uniquenick, mysql_field_value (3), sizeof (uniquenick));
                mystrcpy(user,       uniquenick,            sizeof (user));
                mystrcpy(email,      mysql_field_value (1), sizeof (email));
                mycrc = atoi(mysql_field_value (0));
                if (strcmp(response, gs_login_proof(password, user, server_chall, client_chall))) {
                    // wrong password
                    error_code = 260;
                    mystrcpy(error_msg, "The password provided is incorrect.", sizeof(error_msg));
                    vtype = 17;
                }
            }
        }

        //newuser
        if (vtype == 1) {
        if (strpbrk(password, "!' \"\\*%/") != NULL) {
            //password with special symbols
                error_code = 516;
                mystrcpy(error_msg, "Password is invalid. Certain characters are not accepted in password. Please enter another password.", sizeof(error_msg));
                vtype = 17;
        } else {
            sprintf (temp,"SELECT count(*) as kol FROM player WHERE nick='%s' ",escape_str(uniquenick, esc1) );
            mysql_exec_query(temp);
            if (atoi(mysql_field_value (0))>0) {
                //nick exist
                error_code = 516;
                mystrcpy(error_msg, "The uniquenick is already in use.", sizeof(error_msg));
                vtype = 17;
            } else {
                sprintf (temp,"SELECT count(*) as kol FROM player WHERE email='%s' ",escape_str (email, esc1) );
                mysql_exec_query(temp);
                if (atoi(mysql_field_value (0))>0) {
                    //email exist
                    error_code = 514;
                    mystrcpy(error_msg, "The email is already in use.", sizeof(error_msg));
                    vtype = 17;
                } else {
                    //insert new nick in DB
                    sprintf (temp,"select max(id) as max_id from player");
                    mysql_exec_query(temp);
                    max_id = atoi (mysql_field_value (0));
                    max_id++;

                    sprintf (temp,"INSERT INTO player (id, email, password, passwordenc, nick) "
                                  "VALUES (%d, '%s', '%s', '%s', '%s')",
                                  max_id, escape_str (email, esc1), escape_str (password, esc2), passenc, escape_str (uniquenick, esc3) );
//                                  max_id, email, password, passenc, uniquenick);
                    mysql_exec_query(temp);
                    sprintf (temp,"SELECT id from player WHERE nick='%s' AND passwordenc='%s' ",escape_str (uniquenick, esc1), passenc);
                    mysql_exec_query(temp);
                    mycrc = atoi (mysql_field_value (0));
                }
            }
        }
        }

        //check
        if (vtype == 13) {
            sprintf (temp,"SELECT id from player WHERE nick='%s' AND email='%s' AND password='%s' ",escape_str(nick, esc1), escape_str(email, esc2), escape_str(password, esc3));
            mysql_exec_query(temp);
            mycrc = atoi (mysql_field_value (0));
        }
		
        mysql_close_connection ();
#ifdef WIN32
        ReleaseMutex(hMutex);
#else
        pthread_mutex_unlock(&hMutex);
#endif

        sprintf(userid,    "%u", mycrc);
        sprintf(profileid, "%u", mycrc);
        sprintf(sesskey,   "%u", mycrc);
        sprintf(vmod,      "%u", mycrc);

        if(vtype == 1) {         // newuser
            if(send_login(sd,
                "nur",          "",
                "userid",       userid,
                "profileid",    profileid,
                "id",           id,
                NULL) < 0) goto give_up;
        } else if(vtype == 2) {  // login
            if(send_login(sd,
                "lc",           "2",
                "sesskey",      sesskey,
                "proof",        gs_login_proof(password, user, client_chall, server_chall), // REQUIRED!
                "userid",       userid,
                "profileid",    profileid,
                "uniquenick",   uniquenick,
                "lt",           lt,
                "id",           id,
                NULL) < 0) goto give_up;
        } else if(vtype == 3) {  // logout
            goto give_up;
        } else if(vtype == 4) {  // search
            if(send_login(sd,
                "bsrdone",      "",
                NULL) < 0) goto give_up;
        } else if(vtype == 5) {  // others
            if(send_login(sd,
                "odone",        "",
                NULL) < 0) goto give_up;
        } else if(vtype == 6) {  // pmatch
            if(send_login(sd,
                "psrdone",      "",
                NULL) < 0) goto give_up;
        } else if(vtype == 7) {  // nicks
            if(send_login(sd,
                "nr",           "1",  // user already exists
                "nick",         nick,
                "uniquenick",   uniquenick,
                "ndone",        "",
                NULL) < 0) goto give_up;
        } else if(vtype == 8) {  // auth
            if(send_login(sd,
                "lc",           "2",
                "sesskey",      sesskey,
                "proof",        "0",
                "id",           id,
                NULL) < 0) goto give_up;
        } else if(vtype == 9) {  // authp
            if(send_login(sd,
                "pauthr",       profileid,
                "lid",          LID,
                NULL) < 0) goto give_up;
        } else if(vtype == 10) { // getpd
            if(send_login(sd,
                "getpdr",       "1",
                "lid",          LID,
                "pid",          profileid,
                "mod",          vmod,
                "length",       "52",
                "data",         "0000000000000000000000000000000000000000000000000000",
                NULL) < 0) goto give_up;
            // break;   // uncomment if client freezes!
        } else if(vtype == 11) { // setpd
            if(send_login(sd,
                "setpdr",       "1",
                "lid",          LID,
                "pid",          profileid,
                "mod",          vmod,
                NULL) < 0) goto give_up;
        } else if(vtype == 12) { // getprofile
            if(send_login(sd,
                "pi",           "",
                "profileid",    profileid,
                "nick",         uniquenick,
                "userid",       userid,
                "email",        email,
                "sig",          "00000000000000000000000000000000",
                "uniquenick",   uniquenick,
                "pid",          profileid,
                "firstname",    "firstname",
                "lastname",     "lastname",
                "homepage",     "",
                "zipcode",      "00000",
                "countrycode",  "US",
                "st",           "  ",
                "birthday",     "0",
                "sex",          "0",
                "icquin",       "0",
                "aim",          "",
                "pic",          "0",
                "pmask",        "64",
                "occ",          "0",
                "ind",          "0",
                "inc",          "0",
                "mar",          "0",
                "chc",          "0",
                "i1",           "0",
                "o1",           "0",
                "mp",           "4",    // "1073741831"
                "lon",          "0.000000",
                "lat",          "0.000000",
                "loc",          "",
                "conn",         "1",
                "id",           id,
                NULL) < 0) goto give_up;
        } else if(vtype == 13) { // check
            if(send_login(sd,
                "cur",          "0",
                "pid",          profileid,
                NULL) < 0) goto give_up;
        } else if(vtype == 14) { // addbuddy
            if(send_login(sd,
                "bm",           "2",
                "f",            xprofileid,
                "msg",          reason, //"Please let me add you to my PlayerSpy player list\r\n\r\n|signed|00000000000000000000000000000000",
                NULL) < 0) goto give_up;
        } else if(vtype == 15) { // status
            if(send_login(sd,
                "bm",           "100",
                "f",            profileid,
                "msg",          "|s|1|ss|Room Name|ls|gamename://gsp!gamename/?type=title|ip|0|p|0",
                NULL) < 0) goto give_up;
        } else if(vtype == 16) { // authadd
            if(send_login(sd,
                "bm",           "1",
                "f",            xprofileid,
                "msg",          "I have authorized your request to add me to your list",
                NULL) < 0) goto give_up;
        } else if (vtype == 17) { //error
            sprintf(error_code_string,"%d",error_code);
            if(send_login(sd,
                "error",        "",
                "err",          error_code_string,
                "fatal",        "",
                "errmsg",       error_msg,
                "id",           id,
                NULL) < 0) goto give_up;
        } else if (vtype == 18) { // nicks (not in DB)
            if(send_login(sd,
                "nr",           "0",
                "ndone",        "",
                NULL) <0 ) goto give_up;
        } else {
            if(send_login(sd,
                "pi",           "",
                "pid",          profileid,
                NULL) < 0) goto give_up;
        }
    }

give_up:
    close(sd);
    my_printf("- disconnected\n");
    return(0);
}



int send_login(int sd, ...) {
    va_list ap;
    int     len;
    u_char  buff[1024],
            *p,
            *s;

    p = buff;
    va_start(ap, sd);
    while((s = va_arg(ap, u_char *))) {
        *p++ = '\\';
        p += mystrcpy(p, s, sizeof(buff) - (p - buff));
    }
    va_end(ap);
    if(verbose) my_printf("  %s\\final\\\n", buff);

    if(gs_encoding) gamespy3dxor(buff, p - buff);
    p += mystrcpy(p, "\\final\\", sizeof(buff) - (p - buff));

    len = p - buff;
    if(send(sd, buff, len, 0) != len) return(-1);
    return(0);
}



void gamespy3dxor(u_char *data, int len) {
    static const u_char gamespy[] = "GameSpy3D";
    u_char  *gs;

    gs = (u_char *)gamespy;
    while(len--) {
        *data++ ^= *gs++;
        if(!*gs) gs = (u_char *)gamespy;
    }
}



int recv_parval(int sd, u_char *par, int parsz, u_char *val, int valsz, int *gsoff) {
#define ISPARAMETER (!i)
    static const u_char gamespy[]     = "GameSpy3D",
                        fixed_final[] = "\\final\\";
    int     i,
            finaloff = 0;
    u_char  *p,
            *limit,
            *gs;

    gs     = (u_char *)gamespy + *gsoff;
    par[0] = 0;
    val[0] = 0;

    for(i = 0; i < 2; i++) {
        if(ISPARAMETER) {
            p = par;
            limit = par + parsz - 1;
        } else {
            p = val;
            limit = val + valsz - 1;
        }

        while(p < limit) {
            while(timeout(sd, 120) < 0) {   // useless keep-alive
                if(send_login(sd,
                    "ka",       "",
                    NULL) < 0) return(-1);
            }
            if(recv(sd, p, 1, 0) <= 0) return(-1);
if (extra_log) {
    my_printf(">'%c'\n", *p);
}

            if(gs_encoding) {       // gs_encoding is boring to handle
                if(*p != fixed_final[finaloff]) finaloff = 0;
                if(*p == fixed_final[finaloff]) {
                    if(++finaloff >= (sizeof(fixed_final) - 1)) {
                        p++;        // it must be incremented
                        p -= (sizeof(fixed_final) - 1);
                        *p = 0;
                        if(p == par) return(1);
                        return(2);  // 2 because there are parts of val
                    }
                }
                *p ^= *gs++;
                if(!*gs) gs = (u_char *)gamespy;
            }

            if(*p == '\\') {
                if(p == par) continue;  // for the first '\', not 100% perfect
                break;
            }
            p++;
        }

        *p = 0;
        if(p >= limit) {
            my_printf("- the client sent a too big %s\n", ISPARAMETER ? "parameter" : "value");
            return(-1);
        }
        if(ISPARAMETER && !strcmp(par, "final")) {   // "\final\"
            par[0] = 0; // useless
            return(1);
        }
    }

    *gsoff = gs - (u_char *)gamespy;
    return(0);
}



int mystrcpy(u_char *dst, u_char *src, int max) {
    u_char  *p = dst;

    while(*src && (--max > 0)) {
        *p++ = *src++;
    }
    *p = 0;
    return(p - dst);
}



u_char *create_rand_string(u_int seed, u_char *data, int len, u_char *table) {
    int     tablelen = strlen(table);
    u_char  *p = data;

    while(--len > 0) {
        seed = (seed * 0x343FD) + 0x269EC3;
        seed >>= 1; // blah, sometimes useful
        *p++ = table[seed % tablelen];
    }
    *p = 0;
    return(data);
}



u_short crc16(u_short crc, unsigned char *data, int len) {
    static const u_short crc_lut[256] = {
        0x0000,0xC0C1,0xC181,0x0140,0xC301,0x03C0,0x0280,0xC241,
        0xC601,0x06C0,0x0780,0xC741,0x0500,0xC5C1,0xC481,0x0440,
        0xCC01,0x0CC0,0x0D80,0xCD41,0x0F00,0xCFC1,0xCE81,0x0E40,
        0x0A00,0xCAC1,0xCB81,0x0B40,0xC901,0x09C0,0x0880,0xC841,
        0xD801,0x18C0,0x1980,0xD941,0x1B00,0xDBC1,0xDA81,0x1A40,
        0x1E00,0xDEC1,0xDF81,0x1F40,0xDD01,0x1DC0,0x1C80,0xDC41,
        0x1400,0xD4C1,0xD581,0x1540,0xD701,0x17C0,0x1680,0xD641,
        0xD201,0x12C0,0x1380,0xD341,0x1100,0xD1C1,0xD081,0x1040,
        0xF001,0x30C0,0x3180,0xF141,0x3300,0xF3C1,0xF281,0x3240,
        0x3600,0xF6C1,0xF781,0x3740,0xF501,0x35C0,0x3480,0xF441,
        0x3C00,0xFCC1,0xFD81,0x3D40,0xFF01,0x3FC0,0x3E80,0xFE41,
        0xFA01,0x3AC0,0x3B80,0xFB41,0x3900,0xF9C1,0xF881,0x3840,
        0x2800,0xE8C1,0xE981,0x2940,0xEB01,0x2BC0,0x2A80,0xEA41,
        0xEE01,0x2EC0,0x2F80,0xEF41,0x2D00,0xEDC1,0xEC81,0x2C40,
        0xE401,0x24C0,0x2580,0xE541,0x2700,0xE7C1,0xE681,0x2640,
        0x2200,0xE2C1,0xE381,0x2340,0xE101,0x21C0,0x2080,0xE041,
        0xA001,0x60C0,0x6180,0xA141,0x6300,0xA3C1,0xA281,0x6240,
        0x6600,0xA6C1,0xA781,0x6740,0xA501,0x65C0,0x6480,0xA441,
        0x6C00,0xACC1,0xAD81,0x6D40,0xAF01,0x6FC0,0x6E80,0xAE41,
        0xAA01,0x6AC0,0x6B80,0xAB41,0x6900,0xA9C1,0xA881,0x6840,
        0x7800,0xB8C1,0xB981,0x7940,0xBB01,0x7BC0,0x7A80,0xBA41,
        0xBE01,0x7EC0,0x7F80,0xBF41,0x7D00,0xBDC1,0xBC81,0x7C40,
        0xB401,0x74C0,0x7580,0xB541,0x7700,0xB7C1,0xB681,0x7640,
        0x7200,0xB2C1,0xB381,0x7340,0xB101,0x71C0,0x7080,0xB041,
        0x5000,0x90C1,0x9181,0x5140,0x9301,0x53C0,0x5280,0x9241,
        0x9601,0x56C0,0x5780,0x9741,0x5500,0x95C1,0x9481,0x5440,
        0x9C01,0x5CC0,0x5D80,0x9D41,0x5F00,0x9FC1,0x9E81,0x5E40,
        0x5A00,0x9AC1,0x9B81,0x5B40,0x9901,0x59C0,0x5880,0x9841,
        0x8801,0x48C0,0x4980,0x8941,0x4B00,0x8BC1,0x8A81,0x4A40,
        0x4E00,0x8EC1,0x8F81,0x4F40,0x8D01,0x4DC0,0x4C80,0x8C41,
        0x4400,0x84C1,0x8581,0x4540,0x8701,0x47C0,0x4680,0x8641,
        0x8201,0x42C0,0x4380,0x8341,0x4100,0x81C1,0x8081,0x4040
    };

    while(len--) {
        crc = crc_lut[(*data ^ crc) & 0xff] ^ (crc >> 8);
        data++;
    }
    return(crc);
}



int timeout(int sock, int secs) {
    struct  timeval tout;
    fd_set  fd_read;
    int     err;

    tout.tv_sec  = secs;
    tout.tv_usec = 0;
    FD_ZERO(&fd_read);
    FD_SET(sock, &fd_read);
#ifdef WIN32
    err = select(0, &fd_read, NULL, NULL, &tout);
#else
    err = select(sock + 1, &fd_read, NULL, NULL, &tout);
#endif
    if(err < 0) return(-1); //std_err();
    if(!err) return(-1);
    return(0);
}



#ifndef WIN32
    void std_err(void) {
        perror("\nError");
        exit(1);
    }
#endif



