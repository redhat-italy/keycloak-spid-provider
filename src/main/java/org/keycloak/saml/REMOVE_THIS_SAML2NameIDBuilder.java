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
package org.keycloak.saml;

import org.keycloak.dom.saml.v2.assertion.NameIDType;

import java.net.URI;

public class REMOVE_THIS_SAML2NameIDBuilder {
    private final NameIDType nameIdType;
    private String format;
    private String nameQualifier;
    private String spNameQualifier;

    private REMOVE_THIS_SAML2NameIDBuilder(String value) {
        this.nameIdType = new NameIDType();
        this.nameIdType.setValue(value);
    }

    public static REMOVE_THIS_SAML2NameIDBuilder value(String value) {
        return new REMOVE_THIS_SAML2NameIDBuilder(value);
    }

    public REMOVE_THIS_SAML2NameIDBuilder setFormat(String format) {
        this.format = format;
        return this;
    }

    public REMOVE_THIS_SAML2NameIDBuilder setNameQualifier(String nameQualifier) {
        this.nameQualifier = nameQualifier;
        return this;
    }

    public REMOVE_THIS_SAML2NameIDBuilder setSPNameQualifier(String spNameQualifier) {
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