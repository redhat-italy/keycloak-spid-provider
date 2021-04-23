package org.keycloak.broker.spid;

import org.keycloak.saml.processing.core.saml.v2.writers.SAMLResponseWriter;


import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.EncryptedAssertionType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.dom.saml.v2.protocol.StatusResponseType;
import org.keycloak.dom.saml.v2.protocol.StatusType;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.common.util.StringUtil;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;
import java.util.List;
import org.keycloak.dom.saml.v2.protocol.ExtensionsType;
import javax.xml.crypto.dsig.XMLSignature;

// SPID-UPDATE override method write(...) of SAMLResponseWriter class in order to call SpidSAMLAssertionWriter that adds support for date serialization (XMGregorianCalendar)
// replacement code snippets taken from KC v.9.0.3
public class SpidSAMLResponseWriter extends SAMLResponseWriter {

    private final SpidSAMLAssertionWriter assertionWriter;

    public SpidSAMLResponseWriter(XMLStreamWriter writer) {
        super(writer);
        this.assertionWriter = new SpidSAMLAssertionWriter(writer);
    }

    @Override
    public void write(ResponseType response, boolean forceWriteDsigNamespace) throws ProcessingException {
        Element sig = response.getSignature();

        StaxUtil.writeStartElement(writer, PROTOCOL_PREFIX, JBossSAMLConstants.RESPONSE__PROTOCOL.get(), JBossSAMLURIConstants.PROTOCOL_NSURI.get());

        if (forceWriteDsigNamespace && sig != null && sig.getPrefix() != null && ! sig.hasAttribute("xmlns:" + sig.getPrefix())) {
            StaxUtil.writeNameSpace(writer, sig.getPrefix(), XMLSignature.XMLNS);
        }
        StaxUtil.writeNameSpace(writer, PROTOCOL_PREFIX, JBossSAMLURIConstants.PROTOCOL_NSURI.get());
        StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, JBossSAMLURIConstants.ASSERTION_NSURI.get());

        writeBaseAttributes(response);

        NameIDType issuer = response.getIssuer();
        if (issuer != null) {
            write(issuer, new QName(JBossSAMLURIConstants.ASSERTION_NSURI.get(), JBossSAMLConstants.ISSUER.get(), ASSERTION_PREFIX));
        }

        if (sig != null) {
            StaxUtil.writeDOMElement(writer, sig);
        }
        ExtensionsType extensions = response.getExtensions();
        if (extensions != null && extensions.getAny() != null && ! extensions.getAny().isEmpty()) {
            write(extensions);
        }

        StatusType status = response.getStatus();
        write(status);

        List<ResponseType.RTChoiceType> choiceTypes = response.getAssertions();
        if (choiceTypes != null) {
            for (ResponseType.RTChoiceType choiceType : choiceTypes) {
                AssertionType assertion = choiceType.getAssertion();
                if (assertion != null) {
                    assertionWriter.write(assertion, forceWriteDsigNamespace);
                }

                EncryptedAssertionType encryptedAssertion = choiceType.getEncryptedAssertion();
                if (encryptedAssertion != null) {
                    Element encElement = encryptedAssertion.getEncryptedElement();
                    StaxUtil.writeDOMElement(writer, encElement);
                }
            }
        }
        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }


    /**
     * Write the common attributes for all response types
     *
     * @param statusResponse
     *
     * @throws ProcessingException
     */
    private void writeBaseAttributes(StatusResponseType statusResponse) throws ProcessingException {
        // Attributes
        StaxUtil.writeAttribute(writer, JBossSAMLConstants.ID.get(), statusResponse.getID());
        StaxUtil.writeAttribute(writer, JBossSAMLConstants.VERSION.get(), statusResponse.getVersion());
        StaxUtil.writeAttribute(writer, JBossSAMLConstants.ISSUE_INSTANT.get(), statusResponse.getIssueInstant().toString());

        String destination = statusResponse.getDestination();
        if (StringUtil.isNotNull(destination))
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.DESTINATION.get(), destination);

        String consent = statusResponse.getConsent();
        if (StringUtil.isNotNull(consent))
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.CONSENT.get(), consent);

        String inResponseTo = statusResponse.getInResponseTo();
        if (StringUtil.isNotNull(inResponseTo))
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.IN_RESPONSE_TO.get(), inResponseTo);
    }
}
