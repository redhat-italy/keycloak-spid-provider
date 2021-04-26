package org.keycloak.broker.spid;

import org.keycloak.dom.saml.v2.protocol.NameIDPolicyType;

import java.net.URI;

// SPID-UPDATE Class added to support spNameQualifier setting unavailable in SAML2NameIDPolicyBuilder class of Keycloak v.9.0.3 and required by SpidIdentityProvider class (code taken from keycloak v.12.0.0)
public class SpidSAML2NameIDPolicyBuilder {
    private final NameIDPolicyType policyType;
    private Boolean allowCreate;
    private String spNameQualifier;

    private SpidSAML2NameIDPolicyBuilder(String format) {
        this.policyType = new NameIDPolicyType();
        this.policyType.setFormat(URI.create(format));
    }

    public static SpidSAML2NameIDPolicyBuilder format(String format) {
        return new SpidSAML2NameIDPolicyBuilder(format);
    }

    public SpidSAML2NameIDPolicyBuilder setAllowCreate(Boolean allowCreate) {
        this.allowCreate = allowCreate;
        return this;
    }

    public SpidSAML2NameIDPolicyBuilder setSPNameQualifier(String spNameQualifier) {
        this.spNameQualifier = spNameQualifier;
        return this;
    }

    public NameIDPolicyType build() {
        // SPID-UPDATE disable this if to force null value on allowCreate in order to avoid the adding the attribute in the xml
        // allowCreate in the xml breaks auth request validation
        // if (this.allowCreate != null)
            this.policyType.setAllowCreate(this.allowCreate);

        if (this.spNameQualifier != null)
            this.policyType.setSPNameQualifier(this.spNameQualifier);

        return this.policyType;
    }
}
