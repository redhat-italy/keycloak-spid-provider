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
        // Create the root CessionarioCommittente element
        Element cessionarioCommittenteExtension = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:CessionarioCommittente");
        cessionarioCommittenteExtension.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        Element datiAnagrafici = document.createElementNS(FPA_METADATA_EXTENSIONS_NS, "fpa:DatiAnagrafici");
        datiAnagrafici.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        // Create the IdFiscaleIVA element
        Element idFiscaleIVA = document.createElementNS(FPA_METADATA_EXTENSIONS_NS, "fpa:IdFiscaleIVA");
        idFiscaleIVA.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        // Create the CodiceFiscale element
        Element codiceFiscale = document.createElementNS(FPA_METADATA_EXTENSIONS_NS, "fpa:CodiceFiscale");
        codiceFiscale.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        boolean addIdFiscaleIVA = isNotBlank(config.getBillingIdPaese())
                || isNotBlank(config.getBillingIdCodice());
        boolean addCodiceFiscale = isNotBlank(config.getBillingCodiceFiscale());

        // Create the IdPaese element and set its text content
        if (isNotBlank(config.getBillingIdPaese())) {
            Element idPaese = document.createElementNS(FPA_METADATA_EXTENSIONS_NS, "fpa:IdPaese");
            idPaese.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);
            idPaese.setTextContent(config.getBillingIdPaese());
            idFiscaleIVA.appendChild(idPaese);
        }

        // Create the IdCodice element and set its text content
        if (isNotBlank(config.getBillingIdCodice())) {
            Element idCodice = document.createElementNS(FPA_METADATA_EXTENSIONS_NS, "fpa:IdCodice");
            idCodice.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);
            idCodice.setTextContent(config.getBillingIdCodice());
            idFiscaleIVA.appendChild(idCodice);
        }

        // Create the CodiceFiscale element and set its text content
        if (isNotBlank(config.getBillingCodiceFiscale())) {
            codiceFiscale.setTextContent(config.getBillingCodiceFiscale());

        }

        // Dati Anagrafici Logic (as stated in Page 5 of
        // https://www.agid.gov.it/sites/default/files/repository_files/spid-avviso-n29v3-specifiche_sp_pubblici_e_privati_0.pdf)

        if (addIdFiscaleIVA) {
            datiAnagrafici.appendChild(idFiscaleIVA);
        }

        if (addCodiceFiscale) {
            datiAnagrafici.appendChild(codiceFiscale);
        }

        // Create the Anagrafica element
        Element anagrafica = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:Anagrafica");
        anagrafica.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);
        datiAnagrafici.appendChild(anagrafica);

        boolean addDenominazione = isNotBlank(config.getBillingAnagraficaDenominazione());
        boolean addNomeCognome = isNotBlank(config.getBillingAnagraficaNome())
                && isNotBlank(config.getBillingAnagraficaCognome());
        boolean addTitolo = isNotBlank(config.getBillingAnagraficaTitolo());
        boolean addCodiceEORI = isNotBlank(config.getBillingAnagraficaCodiceEORI());

        // Create the Denominazione element and set its text content
        Element denominazione = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:Denominazione");
        denominazione.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        // Create the Nome element and set its text content
        Element nome = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:Nome");
        nome.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        // Create the Cognome element and set its text content
        Element cognome = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:Cognome");
        cognome.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        // Create the Titolo element and set its text content
        Element titolo = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:Titolo");
        titolo.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        // Create the CodiceEORI element and set its text content
        Element codiceEORI = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:CodiceEORI");
        codiceEORI.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        if (isNotBlank(config.getBillingAnagraficaDenominazione())) {
            denominazione.setTextContent(config.getBillingAnagraficaDenominazione());
        }

        if (isNotBlank(config.getBillingAnagraficaNome())) {
            nome.setTextContent(config.getBillingAnagraficaNome());
        }

        if (isNotBlank(config.getBillingAnagraficaCognome())) {
            cognome.setTextContent(config.getBillingAnagraficaNome());
        }

        if (isNotBlank(config.getBillingAnagraficaTitolo())) {
            titolo.setTextContent(config.getBillingAnagraficaTitolo());
        }

        if (isNotBlank(config.getBillingAnagraficaCodiceEORI())) {
            codiceEORI.setTextContent(config.getBillingAnagraficaCodiceEORI());
        }

        if (addDenominazione) {
            anagrafica.appendChild(denominazione);
        }

        if (addNomeCognome) {
            anagrafica.appendChild(nome);
            anagrafica.appendChild(cognome);
            if (addTitolo) {
                anagrafica.appendChild(titolo);
            }
            if (addCodiceEORI) {
                anagrafica.appendChild(codiceEORI);
            }
        }

        cessionarioCommittenteExtension.appendChild(datiAnagrafici);

        // END datiAnagrafici

        // Create the Sede element
        Element sede = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:Sede");
        sede.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);
        cessionarioCommittenteExtension.appendChild(sede);

        // Create the Indirizzo element and set its text content
        Element indirizzo = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:Indirizzo");
        indirizzo.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        if (isNotBlank(config.getBillingSedeIndirizzo())) {
            indirizzo.setTextContent(config.getBillingSedeIndirizzo());
            sede.appendChild(indirizzo);
        }

        // Create the NumeroCivico element and set its text content
        Element numeroCivico = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:NumeroCivico");
        numeroCivico.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        if (isNotBlank(config.getBillingSedeNumeroCivico())) {
            numeroCivico.setTextContent(config.getBillingSedeNumeroCivico());
            sede.appendChild(numeroCivico);
        }

        // Create the CAP element and set its text content
        Element cap = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:CAP");
        cap.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        if (isNotBlank(config.getBillingSedeCap())) {
            cap.setTextContent(config.getBillingSedeCap());
            sede.appendChild(cap);
        }

        // Create the Comune element and set its text content
        Element comune = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:Comune");
        comune.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        if (isNotBlank(config.getBillingSedeComune())) {
            comune.setTextContent(config.getBillingSedeComune());
            sede.appendChild(comune);
        }

        // Create the Provincia element and set its text content
        Element provincia = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:Provincia");
        provincia.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);
        if (isNotBlank(config.getBillingSedeProvincia())) {
            provincia.setTextContent(config.getBillingSedeProvincia());
            sede.appendChild(provincia);
        }

        // Create the Nazione element and set its text content
        Element nazione = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:Nazione");
        nazione.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);

        if (isNotBlank(config.getBillingSedeNazione())) {
            nazione.setTextContent(config.getBillingSedeNazione());
            sede.appendChild(nazione);
        }
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
        Element terzoIntermediarioSoggettoEmittente = document.createElementNS(FPA_METADATA_EXTENSIONS_NS,
                "fpa:TerzoIntermediarioSoggettoEmittente");

        terzoIntermediarioSoggettoEmittente.setAttributeNS(XMLNS_NS, FPA_QUALIFIED_NAME, FPA_METADATA_EXTENSIONS_NS);
        terzoIntermediarioSoggettoEmittente.setTextContent(billingTerzoIntermediarioSoggettoEmittente);

        billingContactPerson.getExtensions().addExtension(terzoIntermediarioSoggettoEmittente);
    }

    private static boolean isNotBlank(String string) {
        return !isBlank(string);
    }

    private static boolean isBlank(String string) {
        return string == null || string.trim().isEmpty();
    }
}
