package org.keycloak.broker.spid;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.DefaultKeycloakSession;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

import static org.junit.jupiter.api.Assertions.*;

class SpidIdentityProviderFactoryTest {

    private final SpidIdentityProviderFactory factory = new SpidIdentityProviderFactory();

    @Test
    void testCreate() {

        SpidIdentityProviderConfig model = new SpidIdentityProviderConfig();
        model.setBillingAnagraficaNome("Billing Name");
        model.setBillingAnagraficaCognome("Billing Surname");

        SpidIdentityProvider spidIdentityProvider = factory.create(createSession(), model);
        assertConfigIsEqual(model, spidIdentityProvider.getConfig());
    }

    @Test
    void testCreateConfig() {
        var expectedConfig = new SpidIdentityProviderConfig();
        var actualConfig = factory.createConfig();
        assertConfigIsEqual(expectedConfig, actualConfig);
    }

    /**
     * Check the whole config
     *
     * @param expectedConfig config you expect
     * @param actualConfig   config you get
     */
    private void assertConfigIsEqual(SpidIdentityProviderConfig expectedConfig,
                                     SpidIdentityProviderConfig actualConfig) {
        // sed -E 's/^(.*)/\(\) -> assertEquals(expectedConfig.\1,actualConfig.\1\),/p'
        assertAll("Config is equal",
                () -> assertEquals(expectedConfig.getAllowedClockSkew(),
                        actualConfig.getAllowedClockSkew()),
                () -> assertEquals(expectedConfig.getAttributeConsumingServiceIndex(),
                        actualConfig.getAttributeConsumingServiceIndex()),
                () -> assertEquals(expectedConfig.getAttributeConsumingServiceName(),
                        actualConfig.getAttributeConsumingServiceName()),
                () -> assertEquals(expectedConfig.getAuthnContextClassRefs(),
                        actualConfig.getAuthnContextClassRefs()),
                () -> assertEquals(expectedConfig.getAuthnContextComparisonType(),
                        actualConfig.getAuthnContextComparisonType()),
                () -> assertEquals(expectedConfig.getAuthnContextDeclRefs(),
                        actualConfig.getAuthnContextDeclRefs()),
                () -> assertEquals(expectedConfig.getBillingAnagraficaCodiceEORI(),
                        actualConfig.getBillingAnagraficaCodiceEORI()),
                () -> assertEquals(expectedConfig.getBillingAnagraficaCognome(),
                        actualConfig.getBillingAnagraficaCognome()),
                () -> assertEquals(expectedConfig.getBillingAnagraficaDenominazione(),
                        actualConfig.getBillingAnagraficaDenominazione()),
                () -> assertEquals(expectedConfig.getBillingAnagraficaNome(),
                        actualConfig.getBillingAnagraficaNome()),
                () -> assertEquals(expectedConfig.getBillingAnagraficaTitolo(),
                        actualConfig.getBillingAnagraficaTitolo()),
                () -> assertEquals(expectedConfig.getBillingCodiceFiscale(),
                        actualConfig.getBillingCodiceFiscale()),
                () -> assertEquals(expectedConfig.getBillingContactCompany(),
                        actualConfig.getBillingContactCompany()),
                () -> assertEquals(expectedConfig.getBillingContactEmail(),
                        actualConfig.getBillingContactEmail()),
                () -> assertEquals(expectedConfig.getBillingContactPhone(),
                        actualConfig.getBillingContactPhone()),
                () -> assertEquals(expectedConfig.getBillingIdCodice(),
                        actualConfig.getBillingIdCodice()),
                () -> assertEquals(expectedConfig.getBillingIdPaese(),
                        actualConfig.getBillingIdPaese()),
                () -> assertEquals(expectedConfig.getBillingSedeCap(),
                        actualConfig.getBillingSedeCap()),
                () -> assertEquals(expectedConfig.getBillingSedeComune(),
                        actualConfig.getBillingSedeComune()),
                () -> assertEquals(expectedConfig.getBillingSedeIndirizzo(),
                        actualConfig.getBillingSedeIndirizzo()),
                () -> assertEquals(expectedConfig.getBillingSedeNazione(),
                        actualConfig.getBillingSedeNazione()),
                () -> assertEquals(expectedConfig.getBillingSedeNumeroCivico(),
                        actualConfig.getBillingSedeNumeroCivico()),
                () -> assertEquals(expectedConfig.getBillingSedeProvincia(),
                        actualConfig.getBillingSedeProvincia()),
                () -> assertEquals(expectedConfig.getBillingTerzoIntermediarioSoggettoEmittente(),
                        actualConfig.getBillingTerzoIntermediarioSoggettoEmittente()),
                () -> assertEquals(expectedConfig.getEncryptionPublicKey(),
                        actualConfig.getEncryptionPublicKey()),
                () -> assertEquals(expectedConfig.getFiscalCode(), actualConfig.getFiscalCode()),
                () -> assertEquals(expectedConfig.getIdpEntityId(), actualConfig.getIdpEntityId()),
                () -> assertEquals(expectedConfig.getIpaCode(), actualConfig.getIpaCode()),
                () -> assertEquals(expectedConfig.getNameIDPolicyFormat(),
                        actualConfig.getNameIDPolicyFormat()),
                () -> assertEquals(expectedConfig.getOrganizationDisplayNames(),
                        actualConfig.getOrganizationDisplayNames()),
                () -> assertEquals(expectedConfig.getOrganizationNames(),
                        actualConfig.getOrganizationNames()),
                () -> assertEquals(expectedConfig.getOrganizationUrls(),
                        actualConfig.getOrganizationUrls()),
                () -> assertEquals(expectedConfig.getOtherContactCompany(),
                        actualConfig.getOtherContactCompany()),
                () -> assertEquals(expectedConfig.getOtherContactEmail(),
                        actualConfig.getOtherContactEmail()),
                () -> assertEquals(expectedConfig.getOtherContactPhone(),
                        actualConfig.getOtherContactPhone()),
                () -> assertEquals(expectedConfig.getPrincipalAttribute(),
                        actualConfig.getPrincipalAttribute()),
                () -> assertEquals(expectedConfig.getPrincipalType(), actualConfig.getPrincipalType()),
                () -> assertEquals(expectedConfig.getSignatureAlgorithm(),
                        actualConfig.getSignatureAlgorithm()),
                () -> assertEquals(expectedConfig.getSigningCertificate(),
                        actualConfig.getSigningCertificate()),
                () -> assertEquals(expectedConfig.getSingleLogoutServiceUrl(),
                        actualConfig.getSingleLogoutServiceUrl()),
                () -> assertEquals(expectedConfig.getSingleSignOnServiceUrl(),
                        actualConfig.getSingleSignOnServiceUrl()),
                () -> assertEquals(expectedConfig.getVatNumber(), actualConfig.getVatNumber()),
                () -> assertEquals(expectedConfig.getXmlSigKeyInfoKeyNameTransformer(),
                        actualConfig.getXmlSigKeyInfoKeyNameTransformer()),
                () -> assertEquals(expectedConfig.isAddExtensionsElementWithKeyInfo(),
                        actualConfig.isAddExtensionsElementWithKeyInfo()),
                () -> assertEquals(expectedConfig.isAllowCreate(), actualConfig.isAllowCreate()),
                () -> assertEquals(expectedConfig.isBackchannelSupported(),
                        actualConfig.isBackchannelSupported()),
                () -> assertEquals(expectedConfig.isEnabledFromMetadata(),
                        actualConfig.isEnabledFromMetadata()),
                () -> assertEquals(expectedConfig.isForceAuthn(), actualConfig.isForceAuthn()),
                () -> assertEquals(expectedConfig.isPostBindingAuthnRequest(),
                        actualConfig.isPostBindingAuthnRequest()),
                () -> assertEquals(expectedConfig.isPostBindingLogout(),
                        actualConfig.isPostBindingLogout()),
                () -> assertEquals(expectedConfig.isPostBindingResponse(),
                        actualConfig.isPostBindingResponse()),
                () -> assertEquals(expectedConfig.isSignSpMetadata(), actualConfig.isSignSpMetadata()),
                () -> assertEquals(expectedConfig.isSpPrivate(), actualConfig.isSpPrivate()),
                () -> assertEquals(expectedConfig.isValidateSignature(),
                        actualConfig.isValidateSignature()),
                () -> assertEquals(expectedConfig.isWantAssertionsEncrypted(),
                        actualConfig.isWantAssertionsEncrypted()),
                () -> assertEquals(expectedConfig.isWantAssertionsSigned(),
                        actualConfig.isWantAssertionsSigned()),
                () -> assertEquals(expectedConfig.isWantAuthnRequestsSigned(),
                        actualConfig.isWantAuthnRequestsSigned()));
    }

    @Test
    void testGetId() {
        String expected = "saml-spid";
        assertEquals(expected, factory.getId());
    }

    @Test
    void testGetName() {
        String expected = "SPID";
        assertEquals(expected, factory.getName());
    }

    @Test
    void testParseConfig() throws IOException {

        InputStream configStream = Files.newInputStream(Path.of("src/test/resources/real-metadata.xml"));
        InputStream expectedConfigStream = Files
                .newInputStream(Path.of("src/test/resources/parsed-metadata.yaml"));

        Map<String, String> actualConfig = factory.parseConfig(createSession(), configStream);

        Yaml parseExpected = new Yaml();
        Map<String, Object> expectedConfig = parseExpected.load(expectedConfigStream);

        assertEquals(expectedConfig.size(), actualConfig.size());

        actualConfig.forEach(
                (K, V) -> assertEquals(expectedConfig.get(K).toString(), V)
        );

    }

    @Test
    void testConfigPropertiesAreResolvedInBundles() {
        List<ProviderConfigProperty> actualConfigProperties = factory.getConfigProperties();

        ResourceBundle bundle = ResourceBundle.getBundle("provider-config.messages", Locale.ITALIAN);
        List<String> bundleValues = bundle.keySet().stream().map(bundle::getString).toList();

        actualConfigProperties.forEach(pcp ->
                assertAll("Label and help text exists in bundle ",
                        () -> assertTrue(bundleValues.contains(pcp.getLabel())),
                        () -> assertTrue(bundleValues.contains(pcp.getHelpText()))

                ));
    }

    private KeycloakSession createSession() {
        KeycloakSession session = new DefaultKeycloakSession(new DefaultKeycloakSessionFactory());
        session.setAttribute("TestAttribute", "only4Testing");
        return session;
    }
}
