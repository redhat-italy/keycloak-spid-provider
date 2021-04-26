package org.keycloak.broker.spid;

import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.protocol.ExtensionsType;
import org.keycloak.dom.saml.v2.protocol.LogoutRequestType;
import org.keycloak.saml.SAML2LogoutRequestBuilder;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.processing.api.saml.v2.request.SAML2Request;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;

import java.net.URI;
import java.util.Iterator;

// SPID-UPDATE Class extending SAML2LogoutRequestBuilder class to change issuer field type from String to NameIDType (as in keycloak v.12.0.0) required by SpidIdentityProvider class (code for issuer handling taken from keycloak v.12.0.0)
public class SpidSAML2LogoutRequestBuilder extends SAML2LogoutRequestBuilder {
    protected NameIDType issuer;  // SPID-UPDATE changed type from String to NameIDType (as in keycloak v.12.0.0)

    public SpidSAML2LogoutRequestBuilder() {
    }

    public SpidSAML2LogoutRequestBuilder issuer(NameIDType issuer) {
        this.issuer = issuer;
        return this;
    }

    public SpidSAML2LogoutRequestBuilder issuer(String issuer) {
        return issuer(SAML2NameIDBuilder.value(issuer).build());
    }

    public LogoutRequestType createLogoutRequest() throws ConfigurationException {
        LogoutRequestType lort = SAML2Request.createLogoutRequest(this.issuer.getValue());
        lort.setNameID(this.nameId);
        if (this.issuer != null) {
            lort.setIssuer(this.issuer);
        }

        if (this.sessionIndex != null) {
            lort.addSessionIndex(this.sessionIndex);
        }

        if (this.assertionExpiration > 0L) {
            lort.setNotOnOrAfter(XMLTimeUtil.add(lort.getIssueInstant(), this.assertionExpiration * 1000L));
        }

        lort.setDestination(URI.create(this.destination));
        if (!this.extensions.isEmpty()) {
            ExtensionsType extensionsType = new ExtensionsType();
            Iterator var3 = this.extensions.iterator();

            while(var3.hasNext()) {
                NodeGenerator extension = (NodeGenerator)var3.next();
                extensionsType.addExtension(extension);
            }

            lort.setExtensions(extensionsType);
        }

        return lort;
    }
}