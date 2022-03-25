#!/bin/bash
export LC_ALL=C
rm -rf /server/abchosting/database/*.pem
openssl genrsa 2048 > /server/abchosting/database/ca-key.pem
openssl req -new -x509 -nodes -days 99999 -key ca-key.pem -out /server/abchosting/database/ca.pem
openssl req -newkey rsa:2048 -days 99999 -nodes -keyout /server/abchosting/database/server-key.pem -out /server/abchosting/database/server-req.pem
openssl rsa -in /server/abchosting/database/server-key.pem -out /server/abchosting/database/server-key.pem
openssl x509 -req -in /server/abchosting/database/server-req.pem -days 99999 -CA /server/abchosting/database/ca.pem -CAkey /server/abchosting/database/ca-key.pem -set_serial 01 -out /server/abchosting/database/server-cert.pem
openssl req -newkey rsa:2048 -days 99999 -nodes -keyout /server/abchosting/database/client-key.pem -out /server/abchosting/database/client-req.pem
openssl rsa -in /server/abchosting/database/client-key.pem -out /server/abchosting/database/client-key.pem
openssl x509 -req -in /server/abchosting/database/client-req.pem -days 99999 -CA /server/abchosting/database/ca.pem -CAkey /server/abchosting/database/ca-key.pem -set_serial 01 -out /server/abchosting/database/client-cert.pem
chown -v mysql.mysql /server/abchosting/database/{ca,server*}.pem
ls -l /server/abchosting/database/*.pem
exit 0