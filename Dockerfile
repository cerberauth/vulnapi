FROM ubuntu:22.04

WORKDIR /app/

RUN apt-get update
RUN apt-get upgrade -y

RUN apt-get install -y curl
RUN apt-get install -y make

RUN rm -rf /usr/local/go

RUN curl -L -o /tmp/go.tar.gz https://go.dev/dl/go1.23.3.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf /tmp/go.tar.gz

ENV PATH=/usr/local/go/bin:$PATH

COPY ./ /app/

RUN make

ENTRYPOINT [ "/app/vulnapi" ]
