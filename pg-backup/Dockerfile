FROM alpine

RUN apk add --no-cache postgresql-client bash gzip cronie

COPY backup.sh /backup.sh
COPY .pgpass /root/.pgpass
COPY crontab.txt /etc/crontabs/root

RUN chmod +x /backup.sh && chmod 600 /root/.pgpass

CMD ["crond", "-f", "-d", "8"]
