package org.keycloak.broker.spid.mappers;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class SpidUserAttributeMapperTest {


    SpidUserAttributeMapper mapper = new SpidUserAttributeMapper();

    @Test
    void testGetCompatibleProviders() {
        String[] actualCompatibleProviders = mapper.getCompatibleProviders();
        assertArrayEquals(SpidUserAttributeMapper.COMPATIBLE_PROVIDERS, actualCompatibleProviders);
    }

    @Test
    void testGetDisplayType() {
        String actualDisplayType = mapper.getDisplayType();
        assertEquals("SPID Attribute Importer", actualDisplayType);
    }

    @Test
    void testGetId() {
        String actualId = mapper.getId();
        assertEquals(SpidUserAttributeMapper.PROVIDER_ID, actualId);
    }
}
