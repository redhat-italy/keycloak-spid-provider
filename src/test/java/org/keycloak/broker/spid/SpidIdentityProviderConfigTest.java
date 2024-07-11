package org.keycloak.broker.spid;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SpidIdentityProviderConfigTest {


    @ParameterizedTest
    @MethodSource("provideLocales")
    void testConfigPropertiesExistsInBundles(Locale locale) {
        List<ProviderConfigProperty> actualConfigProperties = SpidIdentityProviderConfig.getConfigProperties();

        ResourceBundle bundle = ResourceBundle.getBundle("provider-config.messages", locale);
        actualConfigProperties.forEach(pcp ->
                assertAll("Label and help text exists in bundle ",
                        () -> assertTrue(bundle.containsKey(pcp.getLabel())),
                        () -> assertTrue(bundle.containsKey(pcp.getHelpText()))

                ));
    }

    private static Stream<Arguments> provideLocales() {
        return Stream.of(
                Arguments.of(Locale.ITALIAN),
                Arguments.of(Locale.ENGLISH)
        );
    }
}