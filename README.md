# gs_login_server
for compile under Linux:

gcc -o gs_login_server gs_login_server.c md5.c -I/usr/include/mysql -L/usr/local/lib/mysql -lmysqlclient
