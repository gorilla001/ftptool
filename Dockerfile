FROM golang:1.8.1-alpine

ADD ./ftptool /root/ftptool

ENTRYPOINT ["/root/ftptool"]
