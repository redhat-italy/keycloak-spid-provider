/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.broker.spid;

import static org.keycloak.common.util.UriUtils.checkUrl;

import java.util.List;
import java.util.spi.ResourceBundleProvider;

import org.keycloak.common.enums.SslRequired;
import org.keycloak.dom.saml.v2.protocol.AuthnContextComparisonType;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.saml.SamlPrincipalType;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.util.XmlKeyInfoKeyNameTransformer;
import org.keycloak.services.messages.Messages;

/**
 * @author Pedro Igor
 */
public class SpidIdentityProviderConfig extends IdentityProviderModel {

    public static final XmlKeyInfoKeyNameTransformer DEFAULT_XML_KEY_INFO_KEY_NAME_TRANSFORMER = XmlKeyInfoKeyNameTransformer.NONE;

    public static final String ENTITY_ID = "entityId";
    public static final String IDP_ENTITY_ID = "idpEntityId";
    public static final String ADD_EXTENSIONS_ELEMENT_WITH_KEY_INFO = "addExtensionsElementWithKeyInfo";
    public static final String BACKCHANNEL_SUPPORTED = "backchannelSupported";
    public static final String ENCRYPTION_PUBLIC_KEY = "encryptionPublicKey";
    public static final String FORCE_AUTHN = "forceAuthn";
    public static final String NAME_ID_POLICY_FORMAT = "nameIDPolicyFormat";
    public static final String POST_BINDING_AUTHN_REQUEST = "postBindingAuthnRequest";
    public static final String POST_BINDING_LOGOUT = "postBindingLogout";
    public static final String POST_BINDING_RESPONSE = "postBindingResponse";
    public static final String SIGNATURE_ALGORITHM = "signatureAlgorithm";
    public static final String ENCRYPTION_ALGORITHM = "encryptionAlgorithm";
    public static final String SIGNING_CERTIFICATE_KEY = "signingCertificate";
    public static final String SINGLE_LOGOUT_SERVICE_URL = "singleLogoutServiceUrl";
    public static final String SINGLE_SIGN_ON_SERVICE_URL = "singleSignOnServiceUrl";
    public static final String VALIDATE_SIGNATURE = "validateSignature";
    public static final String PRINCIPAL_TYPE = "principalType";
    public static final String PRINCIPAL_ATTRIBUTE = "principalAttribute";
    public static final String WANT_ASSERTIONS_ENCRYPTED = "wantAssertionsEncrypted";
    public static final String WANT_ASSERTIONS_SIGNED = "wantAssertionsSigned";
    public static final String WANT_AUTHN_REQUESTS_SIGNED = "wantAuthnRequestsSigned";
    public static final String XML_SIG_KEY_INFO_KEY_NAME_TRANSFORMER = "xmlSigKeyInfoKeyNameTransformer";
    public static final String ENABLED_FROM_METADATA  = "enabledFromMetadata";
    public static final String AUTHN_CONTEXT_COMPARISON_TYPE = "authnContextComparisonType";
    public static final String AUTHN_CONTEXT_CLASS_REFS = "authnContextClassRefs";
    public static final String AUTHN_CONTEXT_DECL_REFS = "authnContextDeclRefs";
    public static final String SIGN_SP_METADATA = "signSpMetadata";
    public static final String ALLOW_CREATE = "allowCreate";
    public static final String ATTRIBUTE_CONSUMING_SERVICE_INDEX = "attributeConsumingServiceIndex";
    public static final String ATTRIBUTE_CONSUMING_SERVICE_NAME = "attributeConsumingServiceName";
    public static final String ORGANIZATION_NAMES = "organizationNames";
    public static final String ORGANIZATION_DISPLAY_NAMES = "organizationDisplayNames";
    public static final String ORGANIZATION_URLS = "organizationUrls";
    public static final String OTHER_CONTACT_SP_PRIVATE = "otherContactIsSpPrivate";
    public static final String OTHER_CONTACT_IPA_CODE = "otherContactIpaCode";
    public static final String OTHER_CONTACT_VAT_NUMBER = "otherContactVatNumber";
    public static final String OTHER_CONTACT_FISCAL_CODE = "otherContactFiscalCode";
    public static final String OTHER_CONTACT_COMPANY = "otherContactCompany";
    public static final String OTHER_CONTACT_PHONE = "otherContactPhone";
    public static final String OTHER_CONTACT_EMAIL = "otherContactEmail";
    public static final String BILLING_CONTACT_COMPANY = "billingContactCompany";
    public static final String BILLING_CONTACT_PHONE = "billingContactPhone";
    public static final String BILLING_CONTACT_EMAIL = "billingContactEmail";
    // Cessionario Committente Extension 
    public static final String BILLING_ID_PAESE = "billingIdPaese";
    public static final String BILLING_ID_CODICE = "billingIdCodice";
    public static final String BILLING_CODICE_FISCALE = "billingCodiceFiscale";
    public static final String BILLING_ANAGRAFICA_DENOMINAZIONE = "billingAnagraficaDenominazione";
    public static final String BILLING_ANAGRAFICA_NOME = "billingAnagraficaNome";
    public static final String BILLING_ANAGRAFICA_COGNOME = "billingAnagraficaCognome";
    public static final String BILLING_ANAGRAFICA_TITOLO = "billingAnagraficaTitolo";
    public static final String BILLING_ANAGRAFICA_CODICE_EORI = "billingAnagraficaCodiceEORI";
    public static final String BILLING_SEDE_INDIRIZZO = "billingSedeIndirizzo";
    public static final String BILLING_SEDE_NUMERO_CIVICO = "billingSedeNumeroCivico";
    public static final String BILLING_SEDE_CAP = "billingSedeCap";
    public static final String BILLING_SEDE_COMUNE = "billingSedeComune";
    public static final String BILLING_SEDE_PROVINCIA = "billingSedeProvincia";
    public static final String BILLING_SEDE_NAZIONE = "billingSedeNazione";
    public static final String BILLING_TERZO_INTERMEDIARIO_SOGGETTO_EMITTENTE = "billingTerzoIntermediarioSoggettoEmittente";

    public SpidIdentityProviderConfig() {
    }

    public SpidIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);
    }

    public String getEntityId() {
        return getConfig().get(ENTITY_ID);
    }

    public void setEntityId(String entityId) {
        getConfig().put(ENTITY_ID, entityId);
    }

    public String getIdpEntityId() {
        return getConfig().get(IDP_ENTITY_ID);
    }

    public void setIdpEntityId(String idpEntityId) {
        getConfig().put(IDP_ENTITY_ID, idpEntityId);
    }

    public String getSingleSignOnServiceUrl() {
        return getConfig().get(SINGLE_SIGN_ON_SERVICE_URL);
    }

    public void setSingleSignOnServiceUrl(String singleSignOnServiceUrl) {
        getConfig().put(SINGLE_SIGN_ON_SERVICE_URL, singleSignOnServiceUrl);
    }

    public String getSingleLogoutServiceUrl() {
        return getConfig().get(SINGLE_LOGOUT_SERVICE_URL);
    }

    public void setSingleLogoutServiceUrl(String singleLogoutServiceUrl) {
        getConfig().put(SINGLE_LOGOUT_SERVICE_URL, singleLogoutServiceUrl);
    }

    public boolean isValidateSignature() {
        return Boolean.parseBoolean(getConfig().get(VALIDATE_SIGNATURE));
    }

    public void setValidateSignature(boolean validateSignature) {
        getConfig().put(VALIDATE_SIGNATURE, String.valueOf(validateSignature));
    }

    public boolean isForceAuthn() {
        return Boolean.parseBoolean(getConfig().get(FORCE_AUTHN));
    }

    public void setForceAuthn(boolean forceAuthn) {
        getConfig().put(FORCE_AUTHN, String.valueOf(forceAuthn));
    }

    /**
     * @deprecated Prefer {@link #getSigningCertificates()}}
     */
    @Deprecated
    public String getSigningCertificate() {
        return getConfig().get(SIGNING_CERTIFICATE_KEY);
    }

    /**
     * @deprecated Prefer {@link #addSigningCertificate(String)}}
     * @param signingCertificate
     */
    @Deprecated
    public void setSigningCertificate(String signingCertificate) {
        getConfig().put(SIGNING_CERTIFICATE_KEY, signingCertificate);
    }

    public void addSigningCertificate(String signingCertificate) {
        String crt = getConfig().get(SIGNING_CERTIFICATE_KEY);
        if (crt == null || crt.isEmpty()) {
            getConfig().put(SIGNING_CERTIFICATE_KEY, signingCertificate);
        } else {
            // Note that "," is not coding character per PEM format specification:
            // see https://tools.ietf.org/html/rfc1421, section 4.3.2.4 Step 4: Printable Encoding
            getConfig().put(SIGNING_CERTIFICATE_KEY, crt + "," + signingCertificate);
        }
    }

    public String[] getSigningCertificates() {
        String crt = getConfig().get(SIGNING_CERTIFICATE_KEY);
        if (crt == null || crt.isEmpty()) {
            return new String[] { };
        }
        // Note that "," is not coding character per PEM format specification:
        // see https://tools.ietf.org/html/rfc1421, section 4.3.2.4 Step 4: Printable Encoding
        return crt.split(",");
    }

    public String getNameIDPolicyFormat() {
        return getConfig().get(NAME_ID_POLICY_FORMAT);
    }

    public void setNameIDPolicyFormat(String nameIDPolicyFormat) {
        getConfig().put(NAME_ID_POLICY_FORMAT, nameIDPolicyFormat);
    }

    public boolean isWantAuthnRequestsSigned() {
        return Boolean.parseBoolean(getConfig().get(WANT_AUTHN_REQUESTS_SIGNED));
    }

    public void setWantAuthnRequestsSigned(boolean wantAuthnRequestsSigned) {
        getConfig().put(WANT_AUTHN_REQUESTS_SIGNED, String.valueOf(wantAuthnRequestsSigned));
    }

    public boolean isWantAssertionsSigned() {
        return Boolean.parseBoolean(getConfig().get(WANT_ASSERTIONS_SIGNED));
    }

    public void setWantAssertionsSigned(boolean wantAssertionsSigned) {
        getConfig().put(WANT_ASSERTIONS_SIGNED, String.valueOf(wantAssertionsSigned));
    }

    public boolean isWantAssertionsEncrypted() {
        return Boolean.parseBoolean(getConfig().get(WANT_ASSERTIONS_ENCRYPTED));
    }

    public void setWantAssertionsEncrypted(boolean wantAssertionsEncrypted) {
        getConfig().put(WANT_ASSERTIONS_ENCRYPTED, String.valueOf(wantAssertionsEncrypted));
    }

    public boolean isAddExtensionsElementWithKeyInfo() {
        return Boolean.parseBoolean(getConfig().get(ADD_EXTENSIONS_ELEMENT_WITH_KEY_INFO));
    }

    public void setAddExtensionsElementWithKeyInfo(boolean addExtensionsElementWithKeyInfo) {
        getConfig().put(ADD_EXTENSIONS_ELEMENT_WITH_KEY_INFO, String.valueOf(addExtensionsElementWithKeyInfo));
    }

    public String getSignatureAlgorithm() {
        return getConfig().get(SIGNATURE_ALGORITHM);
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        getConfig().put(SIGNATURE_ALGORITHM, signatureAlgorithm);
    }

    public String getEncryptionAlgorithm() {
        return getConfig().get(ENCRYPTION_ALGORITHM);
    }

    public void setEncryptionAlgorithm(String encryptionAlgorithm) {
        getConfig().put(ENCRYPTION_ALGORITHM, encryptionAlgorithm);
    }

    public String getEncryptionPublicKey() {
        return getConfig().get(ENCRYPTION_PUBLIC_KEY);
    }

    public void setEncryptionPublicKey(String encryptionPublicKey) {
        getConfig().put(ENCRYPTION_PUBLIC_KEY, encryptionPublicKey);
    }

    public boolean isPostBindingAuthnRequest() {
        return Boolean.parseBoolean(getConfig().get(POST_BINDING_AUTHN_REQUEST));
    }

    public void setPostBindingAuthnRequest(boolean postBindingAuthnRequest) {
        getConfig().put(POST_BINDING_AUTHN_REQUEST, String.valueOf(postBindingAuthnRequest));
    }

    public boolean isPostBindingResponse() {
        return Boolean.parseBoolean(getConfig().get(POST_BINDING_RESPONSE));
    }

    public void setPostBindingResponse(boolean postBindingResponse) {
        getConfig().put(POST_BINDING_RESPONSE, String.valueOf(postBindingResponse));
    }

    public boolean isPostBindingLogout() {
        String postBindingLogout = getConfig().get(POST_BINDING_LOGOUT);
        if (postBindingLogout == null) {
            // To maintain unchanged behavior when adding this field, we set the inital value to equal that
            // of the binding for the response:
            return isPostBindingResponse();
        }
        return Boolean.parseBoolean(postBindingLogout);
    }

    public void setPostBindingLogout(boolean postBindingLogout) {
        getConfig().put(POST_BINDING_LOGOUT, String.valueOf(postBindingLogout));
    }

    public boolean isBackchannelSupported() {
        return Boolean.parseBoolean(getConfig().get(BACKCHANNEL_SUPPORTED));
    }

    public void setBackchannelSupported(boolean backchannel) {
        getConfig().put(BACKCHANNEL_SUPPORTED, String.valueOf(backchannel));
    }

    /**
     * Always returns non-{@code null} result.
     * @return Configured ransformer of {@link #DEFAULT_XML_KEY_INFO_KEY_NAME_TRANSFORMER} if not set.
     */
    public XmlKeyInfoKeyNameTransformer getXmlSigKeyInfoKeyNameTransformer() {
        return XmlKeyInfoKeyNameTransformer.from(getConfig().get(XML_SIG_KEY_INFO_KEY_NAME_TRANSFORMER), DEFAULT_XML_KEY_INFO_KEY_NAME_TRANSFORMER);
    }

    public void setXmlSigKeyInfoKeyNameTransformer(XmlKeyInfoKeyNameTransformer xmlSigKeyInfoKeyNameTransformer) {
        getConfig().put(XML_SIG_KEY_INFO_KEY_NAME_TRANSFORMER,
          xmlSigKeyInfoKeyNameTransformer == null
            ? null
            : xmlSigKeyInfoKeyNameTransformer.name());
    }

    public int getAllowedClockSkew() {
        int result = 0;
        String allowedClockSkew = getConfig().get(ALLOWED_CLOCK_SKEW);
        if (allowedClockSkew != null && !allowedClockSkew.isEmpty()) {
            try {
                result = Integer.parseInt(allowedClockSkew);
                if (result < 0) {
                    result = 0;
                }
            } catch (NumberFormatException e) {
                // ignore it and use 0
            }
        }
        return result;
    }

    public void setAllowedClockSkew(int allowedClockSkew) {
        if (allowedClockSkew < 0) {
            getConfig().remove(ALLOWED_CLOCK_SKEW);
        } else {
            getConfig().put(ALLOWED_CLOCK_SKEW, String.valueOf(allowedClockSkew));
        }
    }

    public SamlPrincipalType getPrincipalType() {
        return SamlPrincipalType.from(getConfig().get(PRINCIPAL_TYPE), SamlPrincipalType.SUBJECT);
    }

    public void setPrincipalType(SamlPrincipalType principalType) {
        getConfig().put(PRINCIPAL_TYPE,
            principalType == null
                ? null
                : principalType.name());
    }

    public String getPrincipalAttribute() {
        return getConfig().get(PRINCIPAL_ATTRIBUTE);
    }

    public void setPrincipalAttribute(String principalAttribute) {
        getConfig().put(PRINCIPAL_ATTRIBUTE, principalAttribute);
    }

    public boolean isEnabledFromMetadata() {
        return Boolean.valueOf(getConfig().get(ENABLED_FROM_METADATA ));
    }

    public void setEnabledFromMetadata(boolean enabled) {
        getConfig().put(ENABLED_FROM_METADATA , String.valueOf(enabled));
    }

    public AuthnContextComparisonType getAuthnContextComparisonType() {
        return AuthnContextComparisonType.fromValue(getConfig().getOrDefault(AUTHN_CONTEXT_COMPARISON_TYPE, AuthnContextComparisonType.EXACT.value()));
    }

    public void setAuthnContextComparisonType(AuthnContextComparisonType authnContextComparisonType) {
        getConfig().put(AUTHN_CONTEXT_COMPARISON_TYPE, authnContextComparisonType.value());
    }

    public String getAuthnContextClassRefs() {
        return getConfig().get(AUTHN_CONTEXT_CLASS_REFS);
    }

    public void setAuthnContextClassRefs(String authnContextClassRefs) {
        getConfig().put(AUTHN_CONTEXT_CLASS_REFS, authnContextClassRefs);
    }

    public String getAuthnContextDeclRefs() {
        return getConfig().get(AUTHN_CONTEXT_DECL_REFS);
    }

    public void setAuthnContextDeclRefs(String authnContextDeclRefs) {
        getConfig().put(AUTHN_CONTEXT_DECL_REFS, authnContextDeclRefs);
    }

    public boolean isSignSpMetadata() {
        return Boolean.valueOf(getConfig().get(SIGN_SP_METADATA));
    }

    public void setSignSpMetadata(boolean signSpMetadata) {
        getConfig().put(SIGN_SP_METADATA, String.valueOf(signSpMetadata));
    }
    
    public boolean isAllowCreate() {
        return Boolean.valueOf(getConfig().get(ALLOW_CREATE));
    }

    public void setAllowCreated(boolean allowCreate) {
        getConfig().put(ALLOW_CREATE, String.valueOf(allowCreate));
    }

    public Integer getAttributeConsumingServiceIndex() {
        Integer result = null;
        String strAttributeConsumingServiceIndex = getConfig().get(ATTRIBUTE_CONSUMING_SERVICE_INDEX);
        if (strAttributeConsumingServiceIndex != null && !strAttributeConsumingServiceIndex.isEmpty()) {
            try {
                result = Integer.parseInt(strAttributeConsumingServiceIndex);
                if (result < 0) {
                    result = null;
                }
            } catch (NumberFormatException e) {
                // ignore it and use null
            }
        }
        return result;
    }

    public void setAttributeConsumingServiceIndex(Integer attributeConsumingServiceIndex) {
        if (attributeConsumingServiceIndex == null || attributeConsumingServiceIndex < 0) {
            getConfig().remove(ATTRIBUTE_CONSUMING_SERVICE_INDEX);
        } else {
            getConfig().put(ATTRIBUTE_CONSUMING_SERVICE_INDEX, String.valueOf(attributeConsumingServiceIndex));
        }
    }

    public void setAttributeConsumingServiceName(String attributeConsumingServiceName) {
        getConfig().put(ATTRIBUTE_CONSUMING_SERVICE_NAME, attributeConsumingServiceName);
    }

    public String getAttributeConsumingServiceName() {
        return getConfig().get(ATTRIBUTE_CONSUMING_SERVICE_NAME);
    }

    public String getOrganizationNames() {
        return getConfig().get(ORGANIZATION_NAMES);
    }

    public void setOrganizationNames(String organizationNames) {
        getConfig().put(ORGANIZATION_NAMES, organizationNames);
    }

    public String getOrganizationDisplayNames() {
        return getConfig().get(ORGANIZATION_DISPLAY_NAMES);
    }

    public void setOrganizationDisplayNames(String organizationDisplayNames) {
        getConfig().put(ORGANIZATION_DISPLAY_NAMES, organizationDisplayNames);
    }

    public String getOrganizationUrls() {
        return getConfig().get(ORGANIZATION_URLS);
    }

    public void setOrganizationUrls(String organizationUrls) {
        getConfig().put(ORGANIZATION_URLS, organizationUrls);
    }

    @Override
    public void validate(RealmModel realm) {
        SslRequired sslRequired = realm.getSslRequired();

        checkUrl(sslRequired, getSingleLogoutServiceUrl(), SINGLE_LOGOUT_SERVICE_URL);
        checkUrl(sslRequired, getSingleSignOnServiceUrl(), SINGLE_SIGN_ON_SERVICE_URL);
        //transient name id format is not accepted together with principaltype SubjectnameId
        if (JBossSAMLURIConstants.NAMEID_FORMAT_TRANSIENT.get().equals(getNameIDPolicyFormat()) && SamlPrincipalType.SUBJECT == getPrincipalType())
            throw new IllegalArgumentException("Can not have Transient NameID Policy Format together with SUBJECT Principal Type");
        
    }

    public boolean isSpPrivate() {
        return Boolean.valueOf(getConfig().get(OTHER_CONTACT_SP_PRIVATE));
    }

    public void setSpPrivate(boolean isPrivate) {
        getConfig().put(OTHER_CONTACT_SP_PRIVATE, String.valueOf(isPrivate));
    }

    public String getIpaCode() {
        return getConfig().get(OTHER_CONTACT_IPA_CODE);
    }

    public void setIpaCode(String ipaCode) {
        getConfig().put(OTHER_CONTACT_IPA_CODE, ipaCode);
    }

    public String getVatNumber() {
        return getConfig().get(OTHER_CONTACT_VAT_NUMBER);
    }

    public void setVatNumber(String vatNumber) {
        getConfig().put(OTHER_CONTACT_VAT_NUMBER, vatNumber);
    }

    public String getFiscalCode() {
        return getConfig().get(OTHER_CONTACT_FISCAL_CODE);
    }

    public void setFiscalCode(String fiscalCode) {
        getConfig().put(OTHER_CONTACT_FISCAL_CODE, fiscalCode);
    }

    public String getOtherContactEmail() {
        return getConfig().get(OTHER_CONTACT_EMAIL);
    }

    public String getOtherContactCompany() {
        return getConfig().get(OTHER_CONTACT_COMPANY);
    }

    public String getOtherContactPhone() {
        return getConfig().get(OTHER_CONTACT_PHONE);
    }

    public void setOtherContactEmail(String contactEmail) {
        getConfig().put(OTHER_CONTACT_EMAIL, contactEmail);
    }

    public void setOtherContactCompany(String contactCompany) {
        getConfig().put(OTHER_CONTACT_COMPANY, contactCompany);
    }

    public void setOtherContactPhone(String contactPhone) {
        getConfig().put(OTHER_CONTACT_PHONE, contactPhone);
    }

    public String getBillingContactEmail() {
        return getConfig().get(BILLING_CONTACT_EMAIL);
    }

    public String getBillingContactCompany() {
        return getConfig().get(BILLING_CONTACT_COMPANY);
    }

    public String getBillingContactPhone() {
        return getConfig().get(BILLING_CONTACT_PHONE);
    }

    public void setBillingContactEmail(String contactEmail) {
        getConfig().put(BILLING_CONTACT_EMAIL, contactEmail);
    }

    public void setBillingContactCompany(String contactCompany) {
        getConfig().put(BILLING_CONTACT_COMPANY, contactCompany);
    }

    public void setBillingContactPhone(String contactPhone) {
        getConfig().put(BILLING_CONTACT_PHONE, contactPhone);
    }

    public String getBillingIdPaese() {
        return getConfig().get(BILLING_ID_PAESE);
    }

    public void setBillingIdPaese(String billingIdPaese) {
        getConfig().put(BILLING_ID_PAESE, billingIdPaese);
    }

    public String getBillingIdCodice() {
        return getConfig().get(BILLING_ID_CODICE);
    }

    public void setBillingIdCodice(String billingIdCodice) {
        getConfig().put(BILLING_ID_CODICE, billingIdCodice);
    }

    public String getBillingAnagraficaDenominazione() {
        return getConfig().get(BILLING_ANAGRAFICA_DENOMINAZIONE);
    }

    public void setBillingAnagraficaDenominazione(String billingAnagraficaDenominazione) {
        getConfig().put(BILLING_ANAGRAFICA_DENOMINAZIONE, billingAnagraficaDenominazione);
    }

    public String getBillingSedeIndirizzo() {
        return getConfig().get(BILLING_SEDE_INDIRIZZO);
    }

    public void setBillingSedeIndirizzo(String billingSedeIndirizzo) {
        getConfig().put(BILLING_SEDE_INDIRIZZO, billingSedeIndirizzo);
    }

    public String getBillingSedeNumeroCivico() {
        return getConfig().get(BILLING_SEDE_NUMERO_CIVICO);
    }

    public void setBillingSedeNumeroCivico(String billingSedeNumeroCivico) {
        getConfig().put(BILLING_SEDE_NUMERO_CIVICO, billingSedeNumeroCivico);
    }

    public String getBillingSedeCap() {
        return getConfig().get(BILLING_SEDE_CAP);
    }

    public void setBillingSedeCap(String billingSedeCap) {
        getConfig().put(BILLING_SEDE_CAP, billingSedeCap);
    }

    public String getBillingSedeComune() {
        return getConfig().get(BILLING_SEDE_COMUNE);
    }

    public void setBillingSedeComune(String billingSedeComune) {
        getConfig().put(BILLING_SEDE_COMUNE, billingSedeComune);
    }

    public String getBillingSedeProvincia() {
        return getConfig().get(BILLING_SEDE_PROVINCIA);
    }

    public void setBillingSedeProvincia(String billingSedeProvincia) {
        getConfig().put(BILLING_SEDE_PROVINCIA, billingSedeProvincia);
    }

    public String getBillingSedeNazione() {
        return getConfig().get(BILLING_SEDE_NAZIONE);
    }

    public void setBillingSedeNazione(String billingSedeNazione) {
        getConfig().put(BILLING_SEDE_NAZIONE, billingSedeNazione);
    }

    public String getBillingTerzoIntermediarioSoggettoEmittente() {
        return getConfig().get(BILLING_TERZO_INTERMEDIARIO_SOGGETTO_EMITTENTE);
    }

    public void setBillingTerzoIntermediarioSoggettoEmittente(String billingTerzoIntermediarioSoggettoEmittente) {
        getConfig().put(BILLING_TERZO_INTERMEDIARIO_SOGGETTO_EMITTENTE, billingTerzoIntermediarioSoggettoEmittente);
    }

    public String getBillingCodiceFiscale() {
        return getConfig().get(BILLING_CODICE_FISCALE);
    }
    
    public void setBillingCodiceFiscale(String billingCodiceFiscale) {
        getConfig().put(BILLING_CODICE_FISCALE, billingCodiceFiscale);
    }
    
    public String getBillingAnagraficaNome() {
        return getConfig().get(BILLING_ANAGRAFICA_NOME);
    }
    
    public void setBillingAnagraficaNome(String billingAnagraficaNome) {
        getConfig().put(BILLING_ANAGRAFICA_NOME, billingAnagraficaNome);
    }
    
    public String getBillingAnagraficaCognome() {
        return getConfig().get(BILLING_ANAGRAFICA_COGNOME);
    }
    
    public void setBillingAnagraficaCognome(String billingAnagraficaCognome) {
        getConfig().put(BILLING_ANAGRAFICA_COGNOME, billingAnagraficaCognome);
    }
    
    public String getBillingAnagraficaTitolo() {
        return getConfig().get(BILLING_ANAGRAFICA_TITOLO);
    }
    
    public void setBillingAnagraficaTitolo(String billingAnagraficaTitolo) {
        getConfig().put(BILLING_ANAGRAFICA_TITOLO, billingAnagraficaTitolo);
    }
    
    public String getBillingAnagraficaCodiceEORI() {
        return getConfig().get(BILLING_ANAGRAFICA_CODICE_EORI);
    }
    
    public void setBillingAnagraficaCodiceEORI(String billingAnagraficaCodiceEORI) {
        getConfig().put(BILLING_ANAGRAFICA_CODICE_EORI, billingAnagraficaCodiceEORI);
    }


    public static List<ProviderConfigProperty> getConfigProperties() {
                return ProviderConfigurationBuilder.create()
        .property()
        .name(ORGANIZATION_NAMES)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.organization-names")
        .helpText("identity-provider.spid.organization-names.tooltip")
        .add()

        /*
        .property()
        .name(IDP_ENTITY_ID)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.idpEntityId")
        .helpText("identity-provider.spid.idpEntityId.tooltip")
        .add()
         */

        .property()
        .name(ORGANIZATION_DISPLAY_NAMES)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.organization-display-names")
        .helpText("identity-provider.spid.organization-display-names.tooltip")
        .add()

        .property()
        .name(ORGANIZATION_URLS)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.organization-urls")
        .helpText("identity-provider.spid.organization-urls.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_SP_PRIVATE)
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .label("identity-provider.spid.is-sp-private")
        .helpText("identity-provider.spid.is-sp-private.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_IPA_CODE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.ipaCode")
        .helpText("identity-provider.spid.ipaCode.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_VAT_NUMBER)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.vatNumber")
        .helpText("identity-provider.spid.vatNumber.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_FISCAL_CODE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.fiscalCode")
        .helpText("identity-provider.spid.fiscalCode.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_COMPANY)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.contactCompany.other")
        .helpText("identity-provider.spid.contactCompany.other.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_PHONE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.contactPhone.other")
        .helpText("identity-provider.spid.contactPhone.other.tooltip")
        .add()

        .property()
        .name(OTHER_CONTACT_EMAIL)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.contactEmail.other")
        .helpText("identity-provider.spid.contactEmail.other.tooltip")
        .add()

        .property()
        .name(BILLING_CONTACT_COMPANY)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.contactCompany.billing")
        .helpText("identity-provider.spid.contactCompany.billing.tooltip")
        .add()

        .property()
        .name(BILLING_CONTACT_PHONE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.contactPhone.billing")
        .helpText("identity-provider.spid.contactPhone.billing.tooltip")
        .add()

        .property()
        .name(BILLING_CONTACT_EMAIL)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.contactEmail.billing")
        .helpText("identity-provider.spid.contactEmail.billing.tooltip")
        .add()

        .property()
        .name(BILLING_CODICE_FISCALE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.cessionarioCommittente.codiceFiscale.billing")
        .helpText("identity-provider.spid.cessionarioCommittente.codiceFiscale.billing.tooltip")
        .add()

        .property()
        .name(BILLING_SEDE_INDIRIZZO)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.cessionarioCommittente.sede")
        .helpText("identity-provider.spid.cessionarioCommittente.sede.tooltip")
        .add()

        .property()
        .name(BILLING_ID_CODICE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.cessionarioCommittente.idCodice.billing")
        .helpText("identity-provider.spid.cessionarioCommittente.idCodice.billing.tooltip")
        .add()

        .property()
        .name(BILLING_ID_PAESE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.cessionarioCommittente.idPaese.billing")
        .helpText("identity-provider.spid.cessionarioCommittente.idPaese.billing.tooltip")
        .add()

        .property()
        .name(BILLING_SEDE_CAP)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.cessionarioCommittente.sedeCap.billing")
        .helpText("identity-provider.spid.cessionarioCommittente.sedeCap.billing.tooltip")
        .add()

        .property()
        .name(BILLING_SEDE_PROVINCIA)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.cessionarioCommittente.sedeProvincia.billing")
        .helpText("identity-provider.spid.cessionarioCommittente.sedeProvincia.billing.tooltip")
        .add()

        .property()
        .name(BILLING_SEDE_NAZIONE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("identity-provider.spid.cessionarioCommittente.sedeComune.billing")
        .helpText("identity-provider.spid.cessionarioCommittente.sedeComune.billing.tooltip")
        .add()

        .build();
    }
    
}
