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

import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.common.util.StringUtil;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLAssertionWriter;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;
import java.util.*;

import org.w3c.dom.Element;

import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.ASSERTION_NSURI;

// SPID-UPDATE override method of BaseWriter class in order to add support for date serialization (XMGregorianCalendar)
// replacement code snippet taken from KC v.12.0.0
/**
 * Write the (Spid) SAML Assertion to stream
 *
 */
public class SpidSAMLAssertionWriter extends SAMLAssertionWriter {

    public SpidSAMLAssertionWriter(XMLStreamWriter writer) {
        super(writer);
    }


    @Override
    public void writeAttributeTypeWithoutRootTag(AttributeType attributeType) throws ProcessingException {
        String attributeName = attributeType.getName();
        if (attributeName != null) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.NAME.get(), attributeName);
        }

        String friendlyName = attributeType.getFriendlyName();
        if (StringUtil.isNotNull(friendlyName)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.FRIENDLY_NAME.get(), friendlyName);
        }

        String nameFormat = attributeType.getNameFormat();
        if (StringUtil.isNotNull(nameFormat)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.NAME_FORMAT.get(), nameFormat);
        }

        // Take care of other attributes such as x500:encoding
        Map<QName, String> otherAttribs = attributeType.getOtherAttributes();
        if (otherAttribs != null) {
            List<String> nameSpacesDealt = new ArrayList<>();

            Iterator<QName> keySet = otherAttribs.keySet().iterator();
            while (keySet != null && keySet.hasNext()) {
                QName qname = keySet.next();
                String ns = qname.getNamespaceURI();
                if (!nameSpacesDealt.contains(ns)) {
                    StaxUtil.writeNameSpace(writer, qname.getPrefix(), ns);
                    nameSpacesDealt.add(ns);
                }
                String attribValue = otherAttribs.get(qname);
                StaxUtil.writeAttribute(writer, qname, attribValue);
            }
        }

        List<Object> attributeValues = attributeType.getAttributeValue();
        if (attributeValues != null) {
            for (Object attributeValue : attributeValues) {
                if (attributeValue != null) {
                    if (attributeValue instanceof String) {
                        writeStringAttributeValue((String) attributeValue);
                    } else if (attributeValue instanceof NameIDType) {
                        writeNameIDTypeAttributeValue((NameIDType) attributeValue);
                    // SPID-UPDATE
                    } else if (attributeValue instanceof XMLGregorianCalendar) {
                        writeDateAttributeValue((XMLGregorianCalendar) attributeValue);
                    } else if (attributeValue instanceof Element) {
                        writeElementAttributeValue((Element) attributeValue);
                    // END-OF-SPID-UPDATE
                    } else
                        throw logger.writerUnsupportedAttributeValueError(attributeValue.getClass().getName());
                } else {
                    writeStringAttributeValue(null);
                }
            }
        }
    }

    // SPID-UPDATE
    public void writeDateAttributeValue(XMLGregorianCalendar attributeValue) throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE_VALUE.get(), ASSERTION_NSURI.get());

        StaxUtil.writeNameSpace(writer, JBossSAMLURIConstants.XSI_PREFIX.get(), JBossSAMLURIConstants.XSI_NSURI.get());
        StaxUtil.writeNameSpace(writer, "xs", JBossSAMLURIConstants.XMLSCHEMA_NSURI.get());
        StaxUtil.writeAttribute(writer, "xsi", JBossSAMLURIConstants.XSI_NSURI.get(), "type", "xs:" + attributeValue.getXMLSchemaType().getLocalPart());

        if (attributeValue == null) {
            StaxUtil.writeAttribute(writer, "xsi", JBossSAMLURIConstants.XSI_NSURI.get(), "nil", "true");
        } else {
            StaxUtil.writeCharacters(writer, attributeValue.toString());
        }

        StaxUtil.writeEndElement(writer);
    }

    // SPID-UPDATE
    private void writeElementAttributeValue(Element attributeValue) throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE_VALUE.get(),
                ASSERTION_NSURI.get());
        StaxUtil.writeDOMElement(writer, attributeValue);
        StaxUtil.writeEndElement(writer);
    }
}