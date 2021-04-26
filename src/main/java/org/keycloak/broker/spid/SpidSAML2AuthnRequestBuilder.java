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

import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.RequestedAuthnContextType;
import org.keycloak.saml.processing.core.saml.v2.common.IDGenerator;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;
import org.keycloak.saml.SamlProtocolExtensionsAwareBuilder;
import org.w3c.dom.Document;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;

import org.keycloak.dom.saml.v2.protocol.ExtensionsType;

/**
 */
public class SpidSAML2AuthnRequestBuilder implements SamlProtocolExtensionsAwareBuilder<SpidSAML2AuthnRequestBuilder> {

    private final AuthnRequestType authnRequestType;
    protected String destination;
    protected NameIDType issuer;  // SPID-UPDATE changed type from String to NameIDType (as in keycloak v.12.0.0)
    protected final List<NodeGenerator> extensions = new LinkedList<>();

    public SpidSAML2AuthnRequestBuilder destination(String destination) {
        this.destination = destination;
        return this;
    }

    public SpidSAML2AuthnRequestBuilder issuer(NameIDType issuer) {
        this.issuer = issuer;
        return this;
    }

    public SpidSAML2AuthnRequestBuilder issuer(String issuer) {
        return issuer(SAML2NameIDBuilder.value(issuer).build());
    }

    @Override
    public SpidSAML2AuthnRequestBuilder addExtension(NodeGenerator extension) {
        this.extensions.add(extension);
        return this;
    }

    public SpidSAML2AuthnRequestBuilder() {
        this.authnRequestType = new AuthnRequestType(IDGenerator.create("ID_"), XMLTimeUtil.getIssueInstant());
    }

    public SpidSAML2AuthnRequestBuilder assertionConsumerUrl(String assertionConsumerUrl) {
        this.authnRequestType.setAssertionConsumerServiceURL(URI.create(assertionConsumerUrl));
        return this;
    }

    public SpidSAML2AuthnRequestBuilder assertionConsumerUrl(URI assertionConsumerUrl) {
        this.authnRequestType.setAssertionConsumerServiceURL(assertionConsumerUrl);
        return this;
    }

    public SpidSAML2AuthnRequestBuilder attributeConsumingServiceIndex(Integer attributeConsumingServiceIndex) {
        this.authnRequestType.setAttributeConsumingServiceIndex(attributeConsumingServiceIndex);
        return this;
    }

    public SpidSAML2AuthnRequestBuilder forceAuthn(boolean forceAuthn) {
        this.authnRequestType.setForceAuthn(forceAuthn);
        return this;
    }

    public SpidSAML2AuthnRequestBuilder isPassive(boolean isPassive) {
        this.authnRequestType.setIsPassive(isPassive);
        return this;
    }

    // SPID-UPDATE extra method required to forse null on isPassive value, to avoid adding the element in the xml
    public SpidSAML2AuthnRequestBuilder isPassive(Boolean isPassive) {
        this.authnRequestType.setIsPassive(isPassive);
        return this;
    }

    public SpidSAML2AuthnRequestBuilder nameIdPolicy(SpidSAML2NameIDPolicyBuilder nameIDPolicyBuilder) {
        this.authnRequestType.setNameIDPolicy(nameIDPolicyBuilder.build());
        return this;
    }

    public SpidSAML2AuthnRequestBuilder protocolBinding(String protocolBinding) {
        this.authnRequestType.setProtocolBinding(URI.create(protocolBinding));
        return this;
    }

    public SpidSAML2AuthnRequestBuilder requestedAuthnContext(SAML2RequestedAuthnContextBuilder requestedAuthnContextBuilder) {
        RequestedAuthnContextType requestedAuthnContext = requestedAuthnContextBuilder.build();

        // Only emit the RequestedAuthnContext element if at least a ClassRef or a DeclRef is present
        if (!requestedAuthnContext.getAuthnContextClassRef().isEmpty() ||
                !requestedAuthnContext.getAuthnContextDeclRef().isEmpty())
            this.authnRequestType.setRequestedAuthnContext(requestedAuthnContext);

        return this;
    }

    public Document toDocument() {
        try {
            AuthnRequestType authnRequestType = createAuthnRequest();

            return new SpidSAML2Request().convert(authnRequestType);
        } catch (Exception e) {
            throw new RuntimeException("Could not convert " + authnRequestType + " to a document.", e);
        }
    }

    public AuthnRequestType createAuthnRequest() {
        AuthnRequestType res = this.authnRequestType;
        // SPID-UPDATE
        // REPLACED NameIDType nameIDType = new NameIDType();
        // REPLACED nameIDType.setValue(this.issuer);
        //
        // REPLACED res.setIssuer(nameIDType);
        res.setIssuer(this.issuer);
        // END-OF-SPID-UPDATE

        // SPID-UPDATE
        // REPLACED res.setDestination(URI.create(this.destination));
        String hostDestination = getDestinationHost(this.destination);
        res.setDestination(URI.create(hostDestination));

        if (! this.extensions.isEmpty()) {
            ExtensionsType extensionsType = new ExtensionsType();
            for (NodeGenerator extension : this.extensions) {
                extensionsType.addExtension(extension);
            }
            res.setExtensions(extensionsType);
        }

        return res;
    }

    // SPID-UPDATE (added method)
    private String getDestinationHost(String destination) {

        try {
            URL url = new URL(destination);
            String hostAndProtocol = url.getProtocol() + "://" + url.getHost();

            if (url.getPort() > 0) {
                return hostAndProtocol + ":" + url.getPort();
            }

            return hostAndProtocol;

        } catch (MalformedURLException e) {
            e.printStackTrace();
            // TODO
        }

        return destination;
    }
}