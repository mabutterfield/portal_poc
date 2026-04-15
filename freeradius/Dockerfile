FROM freeradius/freeradius-server:latest

# Copy our custom config files
COPY clients.conf    /etc/freeradius/3.0/clients.conf
COPY authorize       /etc/freeradius/3.0/mods-config/files/authorize
COPY dictionary.fortinet /etc/freeradius/3.0/dictionary.fortinet

# Append Fortinet dictionary to FreeRADIUS main dictionary
RUN echo '$INCLUDE /etc/freeradius/3.0/dictionary.fortinet' \
    >> /etc/freeradius/3.0/dictionary

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1812/udp 1813/udp

ENTRYPOINT ["/entrypoint.sh"]
