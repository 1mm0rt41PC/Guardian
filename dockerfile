FROM python:3-alpine

LABEL "info.immortal-pc.guardian.vendor"="1mm0rt41PC"
LABEL version="1.1"
LABEL description="The Guadian is watch for unusual tcp/http/ssh activity and ban ip via routing. It's a fail2ban like with some integrated feature and simplified configuration. The script install a iptables rule to catch all trafic to closed ports. Then the script parse logs: /var/log/messages /var/log/nginx/access.log"

MAINTAINER "https://github.com/1mm0rt41PC/Guardian"

COPY . /app
RUN apk update --no-cache && apk add --no-cache iptables && rm -rf /var/cache/apk/*

WORKDIR /app
CMD python /app/guardian.py daemon