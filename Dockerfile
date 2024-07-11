FROM registry.redhat.io/rhbk/keycloak-rhel9:22 as builder

# Enable health and metrics support
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

# Configure a database vendor
ENV KC_DB=dev-file

WORKDIR /opt/keycloak
# for demonstration purposes only, please make sure to use proper certificates in production instead
RUN keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=server" -alias server -ext "SAN:c=DNS:localhost,IP:127.0.0.1" -keystore conf/server.keystore

ADD --chown=keycloak:keycloak target/spid-provider.jar /opt/keycloak/providers/spid-provider.jar
COPY --chown=keycloak:keycloak theme/keycloak-spid-only/ /opt/keycloak/themes/keycloak-spid-only/

RUN /opt/keycloak/bin/kc.sh build

FROM registry.redhat.io/rhbk/keycloak-rhel9:22
COPY --from=builder /opt/keycloak/ /opt/keycloak/

EXPOSE 8080
EXPOSE 8443

# change these values to point to a running postgres instance
#ENV KC_DB=postgres
#ENV KC_DB_URL=<DBURL>
#ENV KC_DB_USERNAME=<DBUSERNAME>
#ENV KC_DB_PASSWORD=<DBPASSWORD>
#ENV KC_HOSTNAME=localhost
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]