package org.keycloak.broker.spid.metadata;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.DefaultKeycloakSession;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;

class SpidSpMetadataResourceProviderFactoryTest {

    private SpidSpMetadataResourceProviderFactory factory = new SpidSpMetadataResourceProviderFactory();

    @Test
    void testCreate() {
        RealmResourceProvider actualRealmResourceProvider = factory.create(keycloakSession());
        assertInstanceOf(SpidSpMetadataResourceProvider.class, actualRealmResourceProvider);
    }

    @Test
    void testGetId() {
        String actual = factory.getId();
        assertEquals(SpidSpMetadataResourceProviderFactory.ID, actual);
    }

    private KeycloakSession keycloakSession() {

        KeycloakSession session = new DefaultKeycloakSession(new DefaultKeycloakSessionFactory());
        session.setAttribute("TestAttribute", "only4Testing");

        return session;
    }
}
