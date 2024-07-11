package org.keycloak.broker.spid.mappers;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashMap;
import java.util.Map;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.spid.SpidIdentityProviderFactory;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType.ASTChoiceType;
import org.keycloak.models.IdentityProviderMapperModel;

class SpidUsernameTemplateMapperTest {

    private SpidUsernameTemplateMapper mapper = new SpidUsernameTemplateMapper();

    @Test
    void testGetCompatibleProviders() {
        String[] expected = { SpidIdentityProviderFactory.PROVIDER_ID };
        assertArrayEquals(expected, mapper.getCompatibleProviders());
    }

    @Test
    void testGetDisplayType() {
        String expected = "SPID Username Template Importer";
        assertEquals(expected, mapper.getDisplayType());
    }

    @Test
    void testGetId() {
        String expected = SpidUsernameTemplateMapper.PROVIDER_ID;
        assertEquals(expected, mapper.getId());
    }

    @ParameterizedTest
    @CsvSource({
            "tinit-drcgnn12a46a326k,drcgnn12a46a326k",
            "MPRPSD70B15D971D,MPRPSD70B15D971D",
            "RSSMRA89M01H501Y,RSSMRA89M01H501Y",
            "TINIT-BLLMNO95M10A001X,BLLMNO95M10A001X",
    })
    void testPreprocessFederatedIdentity(String actualFiscalCode, String expectedFiscalCode)
            throws DatatypeConfigurationException {

        IdentityProviderMapperModel testMapperModel = buildMapperModel();
        BrokeredIdentityContext testContext = buildContext(actualFiscalCode);
        mapper.preprocessFederatedIdentity(null, null, testMapperModel, testContext);

        assertEquals(expectedFiscalCode, testContext.getModelUsername());

    }

    private static IdentityProviderMapperModel buildMapperModel() {
        Map<String, String> config = new HashMap<>();
        config.put("template", "${ATTRIBUTE.TEST_FISCAL_CODE}");

        IdentityProviderMapperModel mapperModel = new IdentityProviderMapperModel();
        mapperModel.setConfig(config);
        return mapperModel;
    }

    private static BrokeredIdentityContext buildContext(String codiceFiscale) throws DatatypeConfigurationException {
        XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar();
        AssertionType assertion = new AssertionType("my-spid", now);
        AttributeStatementType attributeStatementType = new AttributeStatementType();
        AttributeType attributeType = new AttributeType("TEST_FISCAL_CODE");
        attributeType.addAttributeValue(codiceFiscale);
        ASTChoiceType astChoiceType = new ASTChoiceType(attributeType);

        attributeStatementType.addAttribute(astChoiceType);
        // assertion.getAttributeStatements().add(attributeStatementType);

        assertion.addStatement(attributeStatementType);

        BrokeredIdentityContext context = new BrokeredIdentityContext("my-spid");
        context.getContextData().put("SAML_ASSERTION", assertion);

        return context;
    }
}
