package org.keycloak.broker.spid.metadata;



import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;


import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.dom.saml.v2.metadata.ContactType;
import org.keycloak.dom.saml.v2.metadata.ContactTypeType;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.w3c.dom.Element;

class SpidSPMetadataResourceHelperTest {

    private SpidSPMetadataResourceHelper helper;
    private static SpidIdentityProviderConfig defaultConfig = new SpidIdentityProviderConfig();
    private static SpidIdentityProviderConfig defaultConfigNomeCognome = new SpidIdentityProviderConfig();


    @BeforeAll
    public static void initClass() {
        //If the test will grow we will consider an object mother pattern
        defaultConfig.setBillingIdPaese("IT");
        defaultConfig.setBillingIdCodice("+390123456789");
        defaultConfig.setBillingAnagraficaDenominazione("Azienda_Destinataria_Fatturazione");
        defaultConfig.setBillingSedeIndirizzo("via [...]");
        defaultConfig.setBillingSedeNumeroCivico("99");
        defaultConfig.setBillingSedeCap("12345");
        defaultConfig.setBillingSedeComune("nome_citta");
        defaultConfig.setBillingSedeProvincia("XY");
        defaultConfig.setBillingSedeNazione("IT");
        defaultConfig.setBillingTerzoIntermediarioSoggettoEmittente("terzo_intermediario_soggetto_emittente");

        defaultConfigNomeCognome.setBillingIdPaese("IT");
        defaultConfigNomeCognome.setBillingIdCodice("+390123456789");
        defaultConfigNomeCognome.setBillingAnagraficaNome("Mario");
        defaultConfigNomeCognome.setBillingAnagraficaCognome("Rossi");
        defaultConfigNomeCognome.setBillingAnagraficaTitolo("Dottore");
        defaultConfigNomeCognome.setBillingSedeIndirizzo("via [...]");
        defaultConfigNomeCognome.setBillingSedeNumeroCivico("99");
        defaultConfigNomeCognome.setBillingSedeCap("12345");
        defaultConfigNomeCognome.setBillingSedeComune("nome_citta");
        defaultConfigNomeCognome.setBillingSedeProvincia("XY");
        defaultConfigNomeCognome.setBillingSedeNazione("IT");
        

    }

    @BeforeEach
    void init() {
        helper = new SpidSPMetadataResourceHelper();
    }

    @Test
    void testCessionarioCommittenteBillingExtension()
            throws ConfigurationException, TransformerException, IOException {
        final String expected = Files.readString(Paths.get("src/test/resources/cessionarioCommittente.xml"));

        ContactType contactType = new ContactType(ContactTypeType.BILLING);

        helper.addCessionarioCommittente(contactType, defaultConfig);

        String actual = toString(contactType.getExtensions().getDomElements().get(0));
        assertEquals(expected, actual);
    }

    @Test
    void testCessionarioCommittenteBillingExtensionNomeCognome()
            throws ConfigurationException, TransformerException, IOException {
        final String expected = Files.readString(Paths.get("src/test/resources/cessionarioCommittenteNomeCognome.xml"));

        ContactType contactType = new ContactType(ContactTypeType.BILLING);

        helper.addCessionarioCommittente(contactType, defaultConfigNomeCognome);

        String actual = toString(contactType.getExtensions().getDomElements().get(0));
        assertEquals(expected, actual);
    }

    @Test
    void testTerzoIntermediarioSoggettoEmittenteBillingExtension()
            throws ConfigurationException, TransformerException, IOException {
        final String expected = "<fpa:TerzoIntermediarioSoggettoEmittente xmlns:fpa=\"http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.2\">terzo_intermediario_soggetto_emittente</fpa:TerzoIntermediarioSoggettoEmittente>\n";

        ContactType contactType = new ContactType(ContactTypeType.BILLING);

        helper.addTerzoIntermediarioSoggettoEmittente(contactType, defaultConfig);

        String actual = toString(contactType.getExtensions().getDomElements().get(0));
        assertEquals(expected, actual);
    }

    private static String toString(Element element) throws TransformerException {
        TransformerFactory factory = TransformerFactory.newDefaultInstance();
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        Writer out = new StringWriter();
        transformer.transform(new DOMSource(element), new StreamResult(out));
        return out.toString();

    }

}
