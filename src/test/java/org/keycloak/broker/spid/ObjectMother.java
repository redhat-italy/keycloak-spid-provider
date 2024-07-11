package org.keycloak.broker.spid;

import org.keycloak.dom.saml.v2.assertion.*;
import org.keycloak.dom.saml.v2.protocol.AuthnContextComparisonType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.dom.saml.v2.protocol.StatusCodeType;
import org.keycloak.dom.saml.v2.protocol.StatusType;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;

public class ObjectMother {

    public static class SamlResponseTypes {

        public static SpidSAMLEndpointHelper CustomHelper(String authnContextClassRefs, AuthnContextComparisonType authnContextComparison) {
            SpidIdentityProviderConfig config = new SpidIdentityProviderConfig();
            config.setIdpEntityId("https://id.lepida.it/idp/shibboleth");
            config.setEntityId("https://spid.agid.gov.it");
            config.setAuthnContextClassRefs(authnContextClassRefs);
            config.setAuthnContextComparisonType(authnContextComparison);
            return new SpidSAMLEndpointHelper(config);
        }


        public static SpidSAMLEndpointHelper DefaultHelper() {
            return CustomHelper("https://www.spid.gov.it/SpidL2", AuthnContextComparisonType.EXACT);
        }

        public static Element samlResponseElement() {
            return samlResponse().getDocumentElement();
        }

        private static Document samlResponse() {
            try {
                return DocumentUtil.getDocument(Files.newInputStream(Path.of("src/test/resources/saml_response.xml")));
            } catch (ParsingException | IOException | ConfigurationException | ProcessingException e) {
                throw new RuntimeException(e);
            }
        }

        public static Element samlAssertion() {
            return DocumentUtil.getElement(samlResponse(), new QName("Assertion"));
        }

        public static ResponseType EmptyResponseType() {
            try {
                return new ResponseType("empty", DatatypeFactory.newInstance().newXMLGregorianCalendar());
            } catch (DatatypeConfigurationException e) {
                throw new RuntimeException(e);
            }
        }

        public static ResponseType CompleteResponseType(String id, String responseTime) {
            try {
                Document samlResponse = samlResponse();
                Element samlAssertion = samlAssertion();

                XMLGregorianCalendar responseTimeCalendar = DatatypeFactory.newInstance().newXMLGregorianCalendar(responseTime);
                ResponseType responseType = new ResponseType(id, responseTimeCalendar);
                responseType.setSignature(DocumentUtil.getElement(samlResponse, new QName("Signature")));


                SubjectConfirmationDataType subjectConfirmationData = new SubjectConfirmationDataType();
                subjectConfirmationData.setAddress("11.22.33.44");
                subjectConfirmationData.setInResponseTo("spid-php_4be997744d3fde7b019fcfcae44d295ab3adb82c21");
                subjectConfirmationData.setNotOnOrAfter(DatatypeFactory.newInstance().newXMLGregorianCalendar("2024-04-10T09:27:28.000Z"));
                subjectConfirmationData.setRecipient("https://login.agid.gov.it/saml/module.php/saml/sp/saml2-acs.php/service");

                SubjectConfirmationType subjectConfirmation = new SubjectConfirmationType();
                subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
                subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

                SubjectType subject = new SubjectType();
                subject.addConfirmation(subjectConfirmation);

                AssertionType id1 = new AssertionType("id", responseTimeCalendar);
                id1.setSubject(subject);

                responseType.addAssertion(new ResponseType.RTChoiceType(id1));
                responseType.getAssertions().get(0).getAssertion().setSignature(DocumentUtil.getChildElement(samlAssertion, new QName("Signature")));
                StatusType statusType = new StatusType();
                StatusCodeType statusCodeType = new StatusCodeType();
                statusCodeType.setValue(URI.create("urn:oasis:names:tc:SAML:2.0:status:Success"));
                statusType.setStatusCode(statusCodeType);
                responseType.setStatus(statusType);
                NameIDType issuer = new NameIDType();
                issuer.setValue("https://id.lepida.it/idp/shibboleth");
                issuer.setFormat(URI.create(SpidSAMLEndpoint.ISSUER_FORMAT));
                responseType.setIssuer(issuer);
                responseType.setInResponseTo("spid-php_4be997744d3fde7b019fcfcae44d295ab3adb82c21");


                return responseType;
            } catch (DatatypeConfigurationException e) {
                throw new RuntimeException(e);
            }
        }

        public static ResponseType CompleteResponseType() {
            return CompleteResponseType("id", "2024-04-10T09:23:28.000Z");
        }

        public static ResponseType UserAnomalies(String statusMessage) {
            ResponseType userAnomaly = CompleteResponseType();

            StatusType status = new StatusType();

            StatusCodeType responderStatusCode = new StatusCodeType();
            responderStatusCode.setValue(URI.create("urn:oasis:names:tc:SAML:2.0:status:Responder"));
            StatusCodeType authnFailedStatusCode = new StatusCodeType();
            responderStatusCode.setValue(URI.create("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"));
            responderStatusCode.setStatusCode(authnFailedStatusCode);

            status.setStatusCode(responderStatusCode);
            status.setStatusMessage(statusMessage);

            userAnomaly.setStatus(status);

            return userAnomaly;
        }
    }
}
