package org.keycloak.broker.spid;

import org.keycloak.dom.saml.v2.assertion.NameIDType;

import java.net.URI;

// SPID-UPDATE Class added because unavailable in Keycloak v.9.0.3 and required by SpidIdentityProvider class (taken from keycloak v.12.0.0)
public class SAML2NameIDBuilder {
    private final NameIDType nameIdType;
    private String format;
    private String nameQualifier;
    private String spNameQualifier;

    private SAML2NameIDBuilder(String value) {
        this.nameIdType = new NameIDType();
        this.nameIdType.setValue(value);
    }

    public static SAML2NameIDBuilder value(String value) {
        return new SAML2NameIDBuilder(value);
    }

    public SAML2NameIDBuilder setFormat(String format) {
        this.format = format;
        return this;
    }

    public SAML2NameIDBuilder setNameQualifier(String nameQualifier) {
        this.nameQualifier = nameQualifier;
        return this;
    }

    public SAML2NameIDBuilder setSPNameQualifier(String spNameQualifier) {
        this.spNameQualifier = spNameQualifier;
        return this;
    }

    public NameIDType build() {
        if (this.format != null)
            this.nameIdType.setFormat(URI.create(this.format));

        if (this.nameQualifier != null)
            this.nameIdType.setNameQualifier(this.nameQualifier);

        if (this.spNameQualifier != null)
            this.nameIdType.setSPNameQualifier(this.spNameQualifier);

        return this.nameIdType;
    }
}