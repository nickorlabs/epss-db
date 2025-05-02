FROM mysql:latest

RUN microdnf install git wget vim jq
RUN sed -i "s/^\(secure-file-priv\=\).*/\1\/opt\/epss-db\/epss-data/g" /etc/my.cnf
RUN cd /opt && git clone https://github.com/hogehuga/epss-db
RUN cp /opt/epss-db/docker/env/.bashrc /root
RUN mkdir -p /opt/epss-db/share /opt/epss-db/epss-data

# Add non-root user and set permissions
RUN useradd -m epssuser \
    && chown -R epssuser:epssuser /opt/epss-db/share /opt/epss-db/epss-data /opt/epss-db/my.cnf || true \
    && chmod 700 /opt/epss-db/my.cnf || true

USER epssuser
