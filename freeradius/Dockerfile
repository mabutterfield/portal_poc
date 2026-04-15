FROM freeradius/freeradius-server:latest

# Copy our custom config files over the image defaults.
# FreeRADIUS 3.x in this image uses /etc/freeradius/ as the config root.
COPY clients.conf        /etc/freeradius/clients.conf
COPY authorize           /etc/freeradius/mods-config/files/authorize
COPY dictionary.fortinet /etc/freeradius/dictionary.fortinet

# Append Fortinet dictionary reference to the main dictionary
RUN echo '$INCLUDE /etc/freeradius/dictionary.fortinet' \
    >> /etc/freeradius/dictionary

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1812/udp 1813/udp

ENTRYPOINT ["/entrypoint.sh"]
