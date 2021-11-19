package org.keycloak.broker.spid.mappers;

import org.keycloak.protocol.saml.SamlProtocol;

/*
Workaround per https://issues.redhat.com/browse/KEYCLOAK-19143
https://github.com/keycloak/keycloak/blob/master/services/src/main/java/org/keycloak/broker/saml/SAMLIdentityProvider.java#L192
https://github.com/keycloak/keycloak/commit/4518b3d3d11a7e5941a97863702cf26b0b1ad8fc
*/
public class SamlProtocolExtension extends SamlProtocol {

    public static final String SAML_REQUEST_ID_BROKER = "SAML_REQUEST_ID_BROKER";
}
