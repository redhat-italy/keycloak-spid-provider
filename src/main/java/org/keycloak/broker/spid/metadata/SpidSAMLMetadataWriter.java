package org.keycloak.broker.spid.metadata;

import org.keycloak.dom.saml.v2.metadata.*;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLMetadataWriter;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;
import java.util.Iterator;
import java.util.List;

/* SPID-UPDATE Class extended from SAMLMetadataWriter to override the following methods:
   - write(ContactType contact)
     extra schema elements required by SPID (Workaround for https://github.com/keycloak/keycloak/pull/7829)
   - writeAttributeConsumingService(AttributeConsumingServiceType attributeConsumer)
     to skip unsupported "isDefault" attribute on <md:AttributeConsumingService ...> tag in the xml metadata file
   (code taken from keycloak v.9.0.3 - SAMLMetadataWriter.java)
*/
public class SpidSAMLMetadataWriter extends SAMLMetadataWriter {
    private final String METADATA_PREFIX = "md";

    public SpidSAMLMetadataWriter(XMLStreamWriter writer) {
        super(writer);
    }

    public void write(ContactType contact) throws ProcessingException {
        StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.CONTACT_PERSON.get(), JBossSAMLURIConstants.METADATA_NSURI.get());

        ContactTypeType attribs = contact.getContactType();
        StaxUtil.writeAttribute(writer, JBossSAMLConstants.CONTACT_TYPE.get(), attribs.value());

        ExtensionsType extensions = contact.getExtensions();
        if (extensions != null) {
            StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.EXTENSIONS__METADATA.get(), JBossSAMLURIConstants.METADATA_NSURI.get());

            for (Object objExtension : extensions.getAny())
            {
                if (objExtension instanceof Element)
                    StaxUtil.writeDOMElement(writer, (Element)objExtension);
            }

            StaxUtil.writeEndElement(writer);
        }

        // Write the name
        String company = contact.getCompany();
        if (company != null) {
            StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.COMPANY.get(), JBossSAMLURIConstants.METADATA_NSURI.get());
            StaxUtil.writeCharacters(writer, company);
            StaxUtil.writeEndElement(writer);
        }
        String givenName = contact.getGivenName();
        if (givenName != null) {
            StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.GIVEN_NAME.get(), JBossSAMLURIConstants.METADATA_NSURI.get());
            StaxUtil.writeCharacters(writer, givenName);
            StaxUtil.writeEndElement(writer);
        }

        String surName = contact.getSurName();
        if (surName != null) {
            StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.SURNAME.get(), JBossSAMLURIConstants.METADATA_NSURI.get());
            StaxUtil.writeCharacters(writer, surName);
            StaxUtil.writeEndElement(writer);
        }

        List<String> emailAddresses = contact.getEmailAddress();
        for (String email : emailAddresses) {
            StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.EMAIL_ADDRESS.get(), JBossSAMLURIConstants.METADATA_NSURI.get());
            StaxUtil.writeCharacters(writer, email);
            StaxUtil.writeEndElement(writer);
        }

        List<String> tels = contact.getTelephoneNumber();
        for (String telephone : tels) {
            StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.TELEPHONE_NUMBER.get(), JBossSAMLURIConstants.METADATA_NSURI.get());
            StaxUtil.writeCharacters(writer, telephone);
            StaxUtil.writeEndElement(writer);
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    public void writeAttributeConsumingService(AttributeConsumingServiceType attributeConsumer) throws ProcessingException {
        StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.ATTRIBUTE_CONSUMING_SERVICE.get(),
                JBossSAMLURIConstants.METADATA_NSURI.get());

        // SPID-UPDATE removed isDefault attribute
//        StaxUtil.writeAttribute(writer, JBossSAMLConstants.ISDEFAULT.get(), "" + attributeConsumer.isIsDefault());
        StaxUtil.writeAttribute(writer, JBossSAMLConstants.INDEX.get(), "" + attributeConsumer.getIndex());

        // Service Name
        List<LocalizedNameType> serviceNames = attributeConsumer.getServiceName();
        for (LocalizedNameType serviceName : serviceNames) {
            writeLocalizedNameType(serviceName, new QName(JBossSAMLURIConstants.METADATA_NSURI.get(), JBossSAMLConstants.SERVICE_NAME.get(),
                    METADATA_PREFIX));
        }

        List<LocalizedNameType> serviceDescriptions = attributeConsumer.getServiceDescription();
        for (LocalizedNameType serviceDescription : serviceDescriptions) {
            writeLocalizedNameType(serviceDescription,
                    new QName(JBossSAMLURIConstants.METADATA_NSURI.get(), JBossSAMLConstants.SERVICE_DESCRIPTION.get(), METADATA_PREFIX));
        }

        List<RequestedAttributeType> requestedAttributes = attributeConsumer.getRequestedAttribute();
        for (RequestedAttributeType requestedAttribute : requestedAttributes) {
            StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.REQUESTED_ATTRIBUTE.get(),
                    JBossSAMLURIConstants.METADATA_NSURI.get());
            Boolean isRequired = requestedAttribute.isIsRequired();
            if (isRequired != null) {
                StaxUtil.writeAttribute(writer, new QName(JBossSAMLConstants.IS_REQUIRED.get()), isRequired.toString());
            }
            writeAttributeTypeWithoutRootTag(requestedAttribute);
            StaxUtil.writeEndElement(writer);
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }
}
