package org.keycloak.broker.spid.metadata;

import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.keycloak.broker.spid.SpidIdentityProviderConfig;
import org.keycloak.dom.saml.v2.metadata.ContactType;
import org.keycloak.dom.saml.v2.metadata.ExtensionsType;

public class SpidSPMetadataResourceHelper {

    private static final String XMLNS_NS = "http://www.w3.org/2000/xmlns/";
    private static final String SPID_METADATA_EXTENSIONS_NS = "https://spid.gov.it/saml-extensions";
    private static final String FPA_METADATA_EXTENSIONS_NS = "http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.2";

    private static final String FPA_QUALIFIED_NAME = "xmlns:fpa";

    /*
     * private SpidIdentityProviderConfig config;
     * 
     * public SpidSPMetadataResourceHelper(SpidIdentityProviderConfig config) {
     * this.config = config;
     * }
     * 
     */

    /**
     * <p>
     * Java class for CessionarioCommittente extension.
     *
     * <p>
     * The following schema fragment shows an example content of this section:
     * 
     * 
     * <pre>
     * &lt;md:Extensions xmlns:fpa="http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.2">
     *  &lt;fpa:CessionarioCommittente>
     *    &lt;fpa:DatiAnagrafici>
     *      &lt;fpa:IdFiscaleIVA>
     *        &lt;fpa:IdPaese>IT&lt;/fpa:IdPaese>
     *        &lt;fpa:IdCodice>+390123456789&lt;/fpa:IdCodice>
     *      &lt;/fpa:IdFiscaleIVA>
     *      &lt;fpa:CodiceFiscale>
     *          RSSMRA80A01H501U
     *      &lt;/fpa:CodiceFiscale>
     *      &lt;fpa:Anagrafica>
     *         &lt;fpa:Denominazione>
     *           Azienda_Destinataria_Fatturazione
     *         &lt;/fpa:Denominazione>
     *         &lt;fpa:Nome>Mario&lt;/fpa:Nome>
     *         &lt;fpa:Cognome>Rossi&lt;/fpa:Cognome>
     *         &lt;fpa:Titolo>Doctor&lt;/fpa:Titolo>
     *         &lt;fpa:CodiceEORI>IT01234567890&lt;/fpa:CodiceEORI>
     *      &lt;/fpa:Anagrafica>
     *    &lt;/fpa:DatiAnagrafici>
     *    &lt;fpa:Sede>
     *      &lt;fpa:Indirizzo>via [...]&lt;/fpa:Indirizzo>
     *      &lt;fpa:NumeroCivico>99&lt;/fpa:NumeroCivico>
     *      &lt;fpa:CAP>12345&lt;/fpa:CAP>
     *      &lt;fpa:Comune>nome_citta&lt;/fpa:Comune>
     *      &lt;fpa:Provincia>XY&lt;/fpa:Provincia>
     *      &lt;fpa:Nazione>IT&lt;/fpa:Nazione>
     *    &lt;/fpa:Sede>
     *  &lt;/fpa:CessionarioCommittente>
     * &lt;/md:Extensions>
     * </pre>
     * 
     * @param billingContactPerson Billing XML Element
     * @param config               IDPConfiguration
     * @throws ConfigurationException when there are issues with the configuration
     */
    public void addCessionarioCommittente(ContactType billingContactPerson, SpidIdentityProviderConfig config)
            throws ConfigurationException {

        // Extensions
        if (billingContactPerson.getExtensions() == null) {
            billingContactPerson.setExtensions(new ExtensionsType());
        }

        Document document = DocumentUtil.createDocument();
        /*
         * Main section logic as stated in Page 5 of the document below:
         */
        // https://www.agid.gov.it/sites/default/files/repository_files/spid-avviso-n29v3-specifiche_sp_pubblici_e_privati_0.pdf

        // Create the root CessionarioCommittente element
        Element cessionarioCommittenteExtension = createFPAElement("fpa:CessionarioCommittente", document);
        // Create the DatiAnagrafici element
        Element datiAnagrafici = createFPAElement("fpa:DatiAnagrafici", document);
        cessionarioCommittenteExtension.appendChild(datiAnagrafici);
        // Create the IdFiscaleIVA element
        Element idFiscaleIVA = createFPAElement("fpa:IdFiscaleIVA", document);
        datiAnagrafici.appendChild(idFiscaleIVA);
        // Create the IdPaese element and set its text content
        Element idPaese = createFPAElement("fpa:IdPaese", document, config.getBillingIdPaese());
        // Create the IdCodice element and set its text content
        Element idCodice = createFPAElement("fpa:IdCodice", document, config.getBillingIdCodice());
        idFiscaleIVA.appendChild(idPaese);
        idFiscaleIVA.appendChild(idCodice);
        if (isNotBlank(config.getBillingCodiceFiscale())) {
            // Create the CodiceFiscale element
            Element codiceFiscale = createFPAElement("fpa:CodiceFiscale", document);
            codiceFiscale.setTextContent(config.getBillingCodiceFiscale());
            datiAnagrafici.appendChild(codiceFiscale);
        }

        // Create the Anagrafica element
        Element anagrafica = createFPAElement("fpa:Anagrafica", document);
        datiAnagrafici.appendChild(anagrafica);

        /*
         * The logic says that you MUST have one between "Denominazione" element
         * or both "Nome" and "Cognome". This logic here is not explicitly enforced.
         */
        if (isNotBlank(config.getBillingAnagraficaDenominazione())) {
            // Create the Denominazione element and set its text content
            Element denominazione = createFPAElement("fpa:Denominazione", document);
            denominazione.setTextContent(config.getBillingAnagraficaDenominazione());
            anagrafica.appendChild(denominazione);
        }
        if (isNotBlank(config.getBillingAnagraficaNome())) {
            // Create the Nome element and set its text content
            Element nome = createFPAElement("fpa:Nome", document);
            nome.setTextContent(config.getBillingAnagraficaNome());
            anagrafica.appendChild(nome);
        }
        if (isNotBlank(config.getBillingAnagraficaCognome())) {
            // Create the Cognome element and set its text content
            Element cognome = createFPAElement("fpa:Cognome", document);
            cognome.setTextContent(config.getBillingAnagraficaCognome());
            anagrafica.appendChild(cognome);
        }
        if (isNotBlank(config.getBillingAnagraficaTitolo())) {
            // Create the Titolo element and set its text content
            Element titolo = createFPAElement("fpa:Titolo", document);
            titolo.setTextContent(config.getBillingAnagraficaTitolo());
            anagrafica.appendChild(titolo);
        }
        if (isNotBlank(config.getBillingAnagraficaCodiceEORI())) {
            // Create the CodiceEORI element and set its text content
            Element codiceEORI = createFPAElement("fpa:CodiceEORI", document);
            codiceEORI.setTextContent(config.getBillingAnagraficaCodiceEORI());
            anagrafica.appendChild(codiceEORI);
        }
        // Create the Sede element
        Element sede = createFPAElement("fpa:Sede", document);
        cessionarioCommittenteExtension.appendChild(sede);
        // Create the Indirizzo element and set its text content
        Element indirizzo = createFPAElement("fpa:Indirizzo", document, config.getBillingSedeIndirizzo());
        sede.appendChild(indirizzo);

        if (isNotBlank(config.getBillingSedeNumeroCivico())) {
            // Create the NumeroCivico element and set its text content
            Element numeroCivico = createFPAElement("fpa:NumeroCivico", document);
            numeroCivico.setTextContent(config.getBillingSedeNumeroCivico());
            sede.appendChild(numeroCivico);
        }
        // Create the CAP element and set its text content
        Element cap = createFPAElement("fpa:CAP", document, config.getBillingSedeCap());
        // Create the Comune element and set its text content
        Element comune = createFPAElement("fpa:Comune", document, config.getBillingSedeComune());
        sede.appendChild(cap);
        sede.appendChild(comune);
        if (isNotBlank(config.getBillingSedeProvincia())) {
            // Create the Provincia element and set its text content
            Element provincia = createFPAElement("fpa:Provincia", document, config.getBillingSedeProvincia());
            sede.appendChild(provincia);
        }
        // Create the Nazione element and set its text content
        Element nazione = createFPAElement("fpa:Nazione", document, config.getBillingSedeNazione());
        sede.appendChild(nazione);

        billingContactPerson.getExtensions().addExtension(cessionarioCommittenteExtension);

    }

    /**
     * <p>
     * Java class for TerzoIntermediarioSoggettoEmittente extension.
     *
     * <p>
     * The following schema fragment shows an example content of this section:
     * 
     * 
     * <pre>
     * &lt;md:Extensions xmlns:fpa="http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.2">
     *   &lt;fpa:TerzoIntermediarioSoggettoEmittente>
     *         terzo_intermediario_soggetto_emittente
     *   &lt;/fpa:TerzoIntermediarioSoggettoEmittente>
     * &lt;/md:Extensions>
     * </pre>
     * 
     * @param billingContactPerson Billing XML Element
     * @param config               IDPConfiguration
     * @throws ConfigurationException when there are issues with the configuration
     */
    public void addTerzoIntermediarioSoggettoEmittente(ContactType billingContactPerson,
            SpidIdentityProviderConfig config) throws ConfigurationException {

        String billingTerzoIntermediarioSoggettoEmittente = config.getBillingTerzoIntermediarioSoggettoEmittente();
        if (isBlank(billingTerzoIntermediarioSoggettoEmittente)) {
            return;
        }
        // Extensions
        if (billingContactPerson.getExtensions() == null) {
            billingContactPerson.setExtensions(new ExtensionsType());
        }

        Document document = DocumentUtil.createDocument();

        // Create the TerzoIntermediarioSoggettoEmittente and set its text content
        Element terzoIntermediarioSoggettoEmittente =  createFPAElement("fpa:TerzoIntermediarioSoggettoEmittente", document, billingTerzoIntermediarioSoggettoEmittente);

        billingContactPerson.getExtensions().addExtension(terzoIntermediarioSoggettoEmittente);
    }

    /*
     *  Some macro
     */

    private static boolean isNotBlank(String string) {
        return !isBlank(string);
    }

    private static boolean isBlank(String string) {
        return string == null || string.trim().isEmpty();
    }

    private Element createFPAElement(String qualifiedName, Document document) {
        Element element = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                qualifiedName);
        element.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);
        return element;
    }

    private Element createFPAElement(String qualifiedName, Document document, String value) {
        Element element = createFPAElement(qualifiedName, document);
        element.setTextContent(value);
        return element;
    }
}
