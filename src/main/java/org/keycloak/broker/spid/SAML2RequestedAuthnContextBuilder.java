package org.keycloak.broker.spid;

import org.keycloak.dom.saml.v2.protocol.AuthnContextComparisonType;
import org.keycloak.dom.saml.v2.protocol.RequestedAuthnContextType;

import java.util.LinkedList;
import java.util.List;

// SPID-UPDATE Class added because unavailable in Keycloak v.9.0.3 and required by SpidIdentityProvider class (taken from keycloak v.12.0.0)
public class SAML2RequestedAuthnContextBuilder {
    private final RequestedAuthnContextType requestedAuthnContextType;
    private AuthnContextComparisonType comparison;
    private List<String> requestedAuthnContextClassRefList;
    private List<String> requestedAuthnContextDeclRefList;

    public SAML2RequestedAuthnContextBuilder() {
        this.requestedAuthnContextType = new RequestedAuthnContextType();
        this.requestedAuthnContextClassRefList = new LinkedList<String>();
        this.requestedAuthnContextDeclRefList = new LinkedList<String>();
    }

    public SAML2RequestedAuthnContextBuilder setComparison(AuthnContextComparisonType comparison) {
        this.comparison = comparison;
        return this;
    }

    public SAML2RequestedAuthnContextBuilder addAuthnContextClassRef(String authnContextClassRef) {
        this.requestedAuthnContextClassRefList.add(authnContextClassRef);
        return this;
    }

    public SAML2RequestedAuthnContextBuilder addAuthnContextDeclRef(String authnContextDeclRef) {
        this.requestedAuthnContextDeclRefList.add(authnContextDeclRef);
        return this;
    }

    public RequestedAuthnContextType build() {
        if (this.comparison != null)
            this.requestedAuthnContextType.setComparison(this.comparison);

        for (String requestedAuthnContextClassRef: this.requestedAuthnContextClassRefList)
            if (requestedAuthnContextClassRef != null && !requestedAuthnContextClassRef.isEmpty())
                this.requestedAuthnContextType.addAuthnContextClassRef(requestedAuthnContextClassRef);

        for (String requestedAuthnContextDeclRef: this.requestedAuthnContextDeclRefList)
            if (requestedAuthnContextDeclRef != null && !requestedAuthnContextDeclRef.isEmpty())
                this.requestedAuthnContextType.addAuthnContextDeclRef(requestedAuthnContextDeclRef);

        return this.requestedAuthnContextType;
    }
}