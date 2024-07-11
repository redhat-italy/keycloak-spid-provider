package org.keycloak.broker.spid;

import org.jboss.logging.Logger;
import org.keycloak.dom.saml.v2.assertion.SubjectConfirmationDataType;
import org.keycloak.dom.saml.v2.assertion.SubjectConfirmationType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StringUtil;
import org.keycloak.services.messages.Messages;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Objects;

/**
 * Externalized the SPID validation method. Using this approach is much simpler create some useful unit tests.
 */
public class SpidSAMLEndpointHelper {

    protected static final Logger logger = Logger.getLogger(SpidSAMLEndpointHelper.class);

    private final SpidIdentityProviderConfig config;

    public SpidSAMLEndpointHelper(SpidIdentityProviderConfig config) {
        this.config = config;
    }

    /**
     * This method verifies the correctness of the response sent by the IdP.
     * The comments written in italian are the actual copy of the error statements
     * given by the AGID testing tool. In this way it is possible to keep track which code block
     * belongs to which test, and its requirement.
     * Last two parameters are obtained from AuthenticationSessionModel
     * <pre>
     *   String requestIssueInstantNote = authSession.getClientNote(JBossSAMLConstants.ISSUE_INSTANT.name());
     *   String assertionConsumerServiceURL = authSession.getClientNote(JBossSAMLConstants.ASSERTION_CONSUMER_SERVICE_URL.name());
     * </pre>
     *
     * @param documentElement             complete document
     * @param assertionElement            single assertion
     * @param expectedRequestId           request id
     * @param responseType                response type
     * @param requestIssueInstantNote     request Issue instant note (extrated from
     * @param assertionConsumerServiceURL assertion consumer service url
     * @return spidcode response error string
     */
    public String verifySpidResponse(Element documentElement,
                                     Element assertionElement,
                                     String expectedRequestId,
                                     ResponseType responseType,
                                     String requestIssueInstantNote,
                                     String assertionConsumerServiceURL) {
        //2: Unsigned Response
        if (responseType.getSignature() == null) {
            return "SpidSamlCheck_02";
        }

        //3: Unsigned Assertion
        if (!responseType.getAssertions().isEmpty() &&
                responseType.getAssertions().get(0).getAssertion().getSignature() == null) {
            return "SpidSamlCheck_03";
        }
        //8: Null ID
        if (StringUtil.isNullOrEmpty(responseType.getID())) {
            return "SpidSamlCheck_08";
        }

        try {
            XMLGregorianCalendar requestIssueInstant = DatatypeFactory.newInstance().
                    newXMLGregorianCalendar(requestIssueInstantNote);

            // 13: IssueInstant correct UTC format -> non valid UTC format throws DateTimeParseException
            Instant.parse(responseType.getIssueInstant().toString());


            XMLGregorianCalendar responseIssueInstant = responseType.getIssueInstant();

            //14: Issue Instant req < Issue Instant Response
            if (responseIssueInstant.compare(requestIssueInstant) != DatatypeConstants.GREATER) {
                return "SpidSamlCheck_14";
            }

            //15: Response Attribute IssueInstant within three minutes of request IssueInstant
            //https://github.com/italia/spid-saml-check/issues/73
            //max tolerance of three minutes
            long responseTimeMillis = responseIssueInstant.toGregorianCalendar().getTimeInMillis();
            long requestTimeMillis = requestIssueInstant.toGregorianCalendar().getTimeInMillis();

            if ((responseTimeMillis - requestTimeMillis) > 0 && (responseTimeMillis - requestTimeMillis) > 180000) {
                return "SpidSamlCheck_15";

            }


            GregorianCalendar now = new GregorianCalendar();
            XMLGregorianCalendar nowXmlGregorianCalendar = DatatypeFactory.newInstance().newXMLGregorianCalendar(now);
            if (responseIssueInstant.compare(nowXmlGregorianCalendar) == DatatypeConstants.GREATER) {
                return "SpidSamlCheck_15";
            }

            //110 IssueInstant must not have milliseconds, this is not an error anymore https://www.spid.gov.it/wp-content/uploads/2021/07/SPID_QAD.pdf
            int responseIssueInstantMillisecond = responseIssueInstant.getMillisecond();
            if (responseIssueInstantMillisecond > 0) {
                logger.debug("responseIssueInstant has milliseconds, SpidSamlCheck_110");
                //return "SpidSamlCheck_110";
            }


        } catch (DatatypeConfigurationException e) {
            logger.error("Could not convert request IssueInstant to XMLGregorianCalendar, wrong format?");
            return "SpidFault_ErrorCode_nr3";
        } catch (DateTimeParseException e) {
            //FIXME: no one emits this exception
            return "SpidSamlCheck_13";
        }

        // 17: Response > InResponseTo missing
        if (!documentElement.hasAttribute("InResponseTo")) {
            return "SpidSamlCheck_17";
        }

        // 16: Response > InResponseTo empty
        String responseInResponseToValue = documentElement.getAttribute("InResponseTo");
        if (responseInResponseToValue.isEmpty()) {
            return "SpidSamlCheck_16";
        }

        // 18: Response > InResponseTo does not match request ID
        if (!responseInResponseToValue.equals(expectedRequestId)) {
            return "SpidSamlCheck_18";
        }

        //22 Unspecified Element Status
        if (responseType.getStatus() != null &&
                responseType.getStatus().getStatusCode() == null &&
                responseType.getStatus().getStatusDetail() == null &&
                responseType.getStatus().getStatusMessage() == null) {
            return "SpidSamlCheck_22";
        }

        //23 Missing Element Status
        if (responseType.getStatus() == null) {
            return "SpidSamlCheck_23";
        }

        //24 Unspecified Element StatusCode
        if (responseType.getStatus() != null &&
                responseType.getStatus().getStatusCode() != null &&
                StringUtil.isNullOrEmpty(responseType.getStatus().getStatusCode().getValue().toString())) {
            return "SpidSamlCheck_24";
        }

        //25 Missing StatusCode: note-> The test fails with code 22 because the
        // element <samlp:Status\> sent by the response is the same. (See response  xml from the SPID testing tool)

        if (responseType.getStatus() != null &&
                responseType.getStatus().getStatusCode() == null) {
            return "SpidSamlCheck_25";
        }

        //26 StatusCode element != Success
        if (responseType.getStatus() != null &&
                responseType.getStatus().getStatusCode() != null &&
                !responseType.getStatus().getStatusCode().getValue().toString().substring(responseType.getStatus().getStatusCode().getValue().toString().lastIndexOf(":") + 1).equals("Success")) {
            return "SpidSamlCheck_26";
        }

        //27 Unspecified Issuer element
        if (responseType.getIssuer() != null &&
                StringUtil.isNullOrEmpty(responseType.getIssuer().getValue())) {
            return "SpidSamlCheck_27";
        }

        //28 Missing element Issuer
        // the test fails with code 1 (test2) because the testing tool sends an unsigned response
        // the control block is included anyhow
        if (responseType.getIssuer() == null) {
            return "SpidSamlCheck_28";
        }

        //29 Element Issuer != EntityID IdP
        if (!responseType.getIssuer().getValue().equalsIgnoreCase(config.getIdpEntityId())) {
            return "SpidSamlCheck_29";
        }

        //30/31  Format di Issuer attribute must be omitted or have the value  urn:oasis:names:tc:SAML:2.0:nameid-format:entity
        if (responseType.getIssuer() != null &&
                responseType.getIssuer().getFormat() != null &&
                !responseType.getIssuer().getFormat().toString().equals(SpidSAMLEndpoint.ISSUER_FORMAT)) {
            return "SpidSamlCheck_30";
        }

        //33 Assertion attribute ID unspecified
        //32/34 checked by keycloak
        String assertionID = assertionElement.getAttribute("ID");
        if (assertionID.isEmpty()) {
            return "SpidSamlCheck_33";
        }

        String assertionIssueInstant = assertionElement.getAttribute("IssueInstant");


        if (!StringUtil.isNullOrEmpty(assertionIssueInstant)) {
            try {
                XMLGregorianCalendar requestIssueInstant = DatatypeFactory.newInstance().
                        newXMLGregorianCalendar(requestIssueInstantNote);
                XMLGregorianCalendar assertionIssueInstantXML = DatatypeFactory.newInstance().
                        newXMLGregorianCalendar(assertionIssueInstant);
                //39 Assertion IssueInstant attribute < Request IssueInstant

                if (assertionIssueInstantXML.compare(requestIssueInstant) == DatatypeConstants.LESSER) {
                    return "SpidSamlCheck_39";
                }

                //40. Assertion IssueInstant attribute > later than 3 minutes from request
                //https://github.com/italia/spid-saml-check/issues/73
                //max tolerance of three minutes
                long assertionTimeMillis = assertionIssueInstantXML.toGregorianCalendar().getTimeInMillis();
                long requestTimemillis = requestIssueInstant.toGregorianCalendar().getTimeInMillis();

                if ((assertionTimeMillis - requestTimemillis) > 0 && (assertionTimeMillis - requestTimemillis) > 180000) {
                    return "SpidSamlCheck_40";

                }

                //110 Assertion IssueInstant with milliseconds, this is not an error anymore https://www.spid.gov.it/wp-content/uploads/2021/07/SPID_QAD.pdf
                int assertionIssueInstantXMLMillisecond = assertionIssueInstantXML.getMillisecond();
                if (assertionIssueInstantXMLMillisecond > 0) {
                    logger.debug("responseIssueInstant (in assertion) has milliseconds, SpidSamlCheck_110");
                    //return "SpidSamlCheck_110";
                }

            } catch (DatatypeConfigurationException e) {
                logger.error("Could not convert request IssueInstant to XMLGregorianCalendar, wrong format?");
                return "SpidFault_ErrorCode_nr3";
            }
        }

        // 42: Assertion > Subject missing
        Element subjectElement = getDocumentElement(assertionElement, "Subject");
        if (subjectElement == null) {
            return "SpidSamlCheck_42";
        }

        // 41: Assertion > Subject empty (Keycloak returns error earlier)
        if (!hasNamedChild(subjectElement)) {
            return "SpidSamlCheck_41";
        }

        //44 Assertion NameID missing
        Element nameID = getDocumentElement(assertionElement, "NameID");
        if (nameID == null) {
            return "SpidSamlCheck_44";
        }

        //43 Assertion NameID unspecified
        if (nameID.getFirstChild() != null && StringUtil.isNullOrEmpty(nameID.getFirstChild().getNodeValue().trim())) {
            return "SpidSamlCheck_43";
        }

        //45/46 Format NameID attribute missing or unspecified
        if (StringUtil.isNullOrEmpty(nameID.getAttribute("Format"))) {
            return "SpidSamlCheck_4546";
        }

        //47 Format NameID attribute !=  urn:oasis:names:tc:SAML:2.0:nameidformat:transient
        if (!StringUtil.isNullOrEmpty(nameID.getAttribute("Format")) && !nameID.getAttribute("Format").equals(SpidSAMLEndpoint.ASSERTION_NAMEID_FORMAT)) {
            return "SpidSamlCheck_47";

        }
        //48/49 Assertion NameQualifier unspecified
        if (StringUtil.isNullOrEmpty(nameID.getAttribute("NameQualifier"))) {
            return "SpidSamlCheck_4849";
        }

        // 52: Assertion > Subject > Confirmation missing
        Element subjectConfirmationElement = getDocumentElement(subjectElement, "SubjectConfirmation");

        if (subjectConfirmationElement == null) {
            return "SpidSamlCheck_52";
        }

        // 51: Assertion > Subject > Confirmation empty
        if (!hasNamedChild(subjectConfirmationElement)) {
            return "SpidSamlCheck_51";
        }

        // 53: Assertion > Subject > Confirmation > Method missing
        if (!subjectConfirmationElement.hasAttribute("Method")) {
            return "SpidSamlCheck_53";
        }

        // 54: Assertion > Subject > Confirmation > Method empty
        String subjectConfirmationMethodValue = subjectConfirmationElement.getAttribute("Method");
        if (subjectConfirmationMethodValue.isEmpty()) {
            return "SpidSamlCheck_54";
        }

        // 55: Assertion > Subject > Confirmation > Method is not JBossSAMLURIConstants.SUBJECT_CONFIRMATION_BEARER
        if (!subjectConfirmationMethodValue.equals(JBossSAMLURIConstants.SUBJECT_CONFIRMATION_BEARER.get())) {
            return "SpidSamlCheck_55";
        }

        // 56: Assertion > Subject > Confirmation > SubjectConfirmationData missing. Testing tool xml snippet same as 51
        Element subjectConfirmationDataElement = getDocumentElement(subjectConfirmationElement, "SubjectConfirmationData");

        if (subjectConfirmationDataElement == null) {
            return "SpidSamlCheck_56";
        }

        // 58: Assertion > Subject > Confirmation > SubjectConfirmationData > Recipient missing
        if (!subjectConfirmationDataElement.hasAttribute("Recipient")) {
            return "SpidSamlCheck_58";
        }

        // 59: Assertion > Subject > Confirmation > SubjectConfirmationData > different than AssertionConsumerServiceURL
        String recipient = subjectConfirmationDataElement.getAttribute("Recipient");
        if (!StringUtil.isNullOrEmpty(recipient) && !recipient.trim().equals(assertionConsumerServiceURL.trim())) {
            return "SpidSamlCheck_59";
        }

        // 57: Assertion > Subject > Confirmation > SubjectConfirmationData > Recipient is empty
        String subjectConfirmationDataRecipientValue = subjectConfirmationDataElement.getAttribute("Recipient");
        if (subjectConfirmationDataRecipientValue.isEmpty()) {
            return "SpidSamlCheck_57";
        }

        // 61: Assertion > Subject > Confirmation > SubjectConfirmationData > InResponseTo missing
        if (!subjectConfirmationDataElement.hasAttribute("InResponseTo")) {
            return "SpidSamlCheck_61";
        }

        // 60: Assertion > Subject > Confirmation > SubjectConfirmationData > InResponseTo is empty
        String subjectConfirmationDataInResponseToValue = subjectConfirmationDataElement.getAttribute("InResponseTo");
        if (subjectConfirmationDataInResponseToValue.isEmpty()) {
            return "SpidSamlCheck_60";
        }

        // 62: Assertion > Subject > Confirmation > SubjectConfirmationData > InResponseTo does not match request ID
        if (!subjectConfirmationDataInResponseToValue.equals(expectedRequestId)) {
            return "SpidSamlCheck_62";
        }

        // 64:  Assertion > Subject > Confirmation > SubjectConfirmationData > NotOnOrAfter missing
        String notOnOrAfter = subjectConfirmationDataElement.getAttribute("NotOnOrAfter");
        if (StringUtil.isNullOrEmpty(notOnOrAfter.trim())) {
            return "SpidSamlCheck_64";
        }

        try {
            // 66:  Assertion > Subject > Confirmation > SubjectConfirmationData > NotOnOrAfter before response reception
            XMLGregorianCalendar notOnOrAfterXMLGregorian = DatatypeFactory.newInstance().
                    newXMLGregorianCalendar(notOnOrAfter);
            XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar());

            if (notOnOrAfterXMLGregorian.compare(now) == DatatypeConstants.LESSER) {
                return "SpidSamlCheck_66";
            }

        } catch (DatatypeConfigurationException e) {
            logger.error("Could not convert request NotOnOrAfter to XMLGregorianCalendar, wrong format?");
            return "SpidFault_ErrorCode_nr3";
        }
        // 67:  Assertion > Issuer non specified
        Element issuerElement = getDocumentElement(assertionElement, "Issuer");
        if (issuerElement != null &&
                (issuerElement.getFirstChild() == null ||
                        StringUtil.isNullOrEmpty(issuerElement.getFirstChild().getNodeValue()))) {
            return "SpidSamlCheck_67";

        }
        // 68:  Assertion > Issuer missing
        if (issuerElement == null) {
            return "SpidSamlCheck_68";

        }

        //69 Assertion > Issuer != entityID idp
        if (!issuerElement.getFirstChild().getNodeValue().equals(config.getIdpEntityId())) {
            return "SpidSamlCheck_69";
        }
        //70 71 Assertion > Issuer > Format not specified or null
        String format = issuerElement.getAttribute("Format");
        if (StringUtil.isNullOrEmpty(format)) {
            return "SpidSamlCheck_7071";
        }

        //72 Assertion > Issuer > Format different than constant
        if (!format.equals(SpidSAMLEndpoint.ASSERTION_ISSUER_FORMAT)) {
            return "SpidSamlCheck_72";
        }

        //73 Assertion > Conditions missing
        Element conditionsElement = getDocumentElement(assertionElement, "Conditions");
        if (conditionsElement != null && !hasNamedChild(conditionsElement)) {
            return "SpidSamlCheck_73";
        }
        //74 Assertion > Conditions is null
        if (conditionsElement == null) {
            return "SpidSamlCheck_74";
        }
        //75-76 Assertion > Conditions > NotBefore null or empty
        String notBefore = conditionsElement.getAttribute("NotBefore");
        if (StringUtil.isNullOrEmpty(notBefore)) {
            return "SpidSamlCheck_7576";
        }

        //78 Assertion > Condition > NotBefore after response
        try {
            XMLGregorianCalendar notBeforeXmlGregorian = DatatypeFactory.newInstance().
                    newXMLGregorianCalendar(notBefore);
            XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar());

            if (notBeforeXmlGregorian.compare(now) == DatatypeConstants.GREATER) {
                return "SpidSamlCheck_78";
            }

        } catch (DatatypeConfigurationException e) {
            logger.error("Could not convert request NotOnOrAfter to XMLGregorianCalendar, wrong format?");
            return "SpidFault_ErrorCode_nr3";
        }

        //79-80 Assertion > Condition > NotOnOrAfter missing or not specified
        String conditionsNotOnOrAfter = conditionsElement.getAttribute("NotOnOrAfter");
        if (StringUtil.isNullOrEmpty(conditionsNotOnOrAfter.trim())) {
            return "SpidSamlCheck_7980";
        }

        //82 Assertion > Condition > NotOnOrAfter before response
        try {
            XMLGregorianCalendar conditionsNotOnOrAfterXmlGregorian = DatatypeFactory.newInstance().
                    newXMLGregorianCalendar(conditionsNotOnOrAfter);
            XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar());

            if (conditionsNotOnOrAfterXmlGregorian.compare(now) == DatatypeConstants.LESSER) {
                return "SpidSamlCheck_82";
            }

        } catch (DatatypeConfigurationException e) {
            logger.error("Could not convert request NotOnOrAfter to XMLGregorianCalendar, wrong format?");
            return "SpidFault_ErrorCode_nr3";
        }

        //86 Assertion > Condition > Audience > AudienceRestriction missing (note: testing tool xml same as #83)
        Element audienceRestrictionElement = getDocumentElement(conditionsElement, "AudienceRestriction");
        Element audience = getDocumentElement(audienceRestrictionElement, "Audience");

        //83 Assertion > Condition > AudienceRestriction not specified
        if (!hasNamedChild(audienceRestrictionElement)) {
            return "SpidSamlCheck_83";
        }

        //85  86 Assertion > Condition > AudienceRestriction > Audience not specified or missing (note: testing tool 86 xml same as #83)
        if (audience == null || audience.getFirstChild() == null || StringUtil.isNullOrEmpty(audience.getFirstChild().getNodeValue())) {
            return "SpidSamlCheck_8586";
        }


        //84 Assertion > Condition > AudienceRestriction null (testing tool yaml snippet same as #73)
        if (audienceRestrictionElement == null) {
            return "SpidSamlCheck_84";
        }

        //87 Assertion > Condition > AudienceRestriction > Audience != EntityID SP
        String spEntityId = config.getEntityId();
        if (audience.getFirstChild() != null &&
                !StringUtil.isNullOrEmpty(audience.getFirstChild().getNodeValue()) &&
                !audience.getFirstChild().getNodeValue().equals(spEntityId)) {

            return "SpidSamlCheck_87";

        }

        //88 Assertion > AuthnStatement not specified
        Element authnStatement = getDocumentElement(assertionElement, "AuthnStatement");
        if (authnStatement != null && !hasNamedChild(authnStatement)) {
            return "SpidSamlCheck_88";
        }
        //89 Assertion > AuthnStatement null
        if (authnStatement == null) {
            return "SpidSamlCheck_89";

        }
        //90 Assertion > AuthnStatement > AuthnContext not specified
        Element authnContextElement = getDocumentElement(authnStatement, "AuthnContext");
        if (authnContextElement != null && !hasNamedChild(authnContextElement)) {
            return "SpidSamlCheck_90";
        }
        //91 Assertion > AuthnContext > AuthnStatement null note: from IDP same xml response block as #88
        if (authnContextElement == null) {
            return "SpidSamlCheck_91";

        }

        //92 Assertion > AuthnStatement > AuthnContextClassRef unspecified
        Element authnContextClassRef = getDocumentElement(authnContextElement, "AuthnContextClassRef");
        if (authnContextClassRef != null &&
                (authnContextClassRef.getFirstChild() == null ||
                        StringUtil.isNullOrEmpty(authnContextClassRef.getFirstChild().getNodeValue()))) {
            return "SpidSamlCheck_92";

        }

        //93 Assertion > AuthnStatement > AuthnContextClassRef missing note: response snippet same as #90
        if (authnContextClassRef == null) {
            return "SpidSamlCheck_93";
        }
        /*
         *nota: se vi sono più spidLevel specificati in keycloak, la response avrà sempre e solo il primo
         * Non essendo specificato nel tool il preciso comportamento in casi di vari livelli configurati ma solo uno
         * inviato dalla request, si sceglie di controllare che il livello della response sia contenuto tra i livelli
         * configurati su kc (quindi nella config della request)
         */

        //94 Assertion > AuthContextClassRef spid level different from request. This block also implies #95 #96 #97
        String responseSpidLevel = authnContextClassRef.getFirstChild().getNodeValue();
        List<String> requestSpidLevels = Arrays.asList(config.getAuthnContextClassRefs().replaceAll("[\"\\[\\](){}]", "").trim().split(","));

        int spidLevelFromResponse = extractSpidLevel(authnContextClassRef.getFirstChild().getNodeValue());
        // only the first on configuration
        int spidLevelFromConfig = extractSpidLevel(requestSpidLevels.get(0));
        if (spidLevelFromResponse < 1 || spidLevelFromConfig < 1) {
            return "SpidSamlCheck_97";
        }

        int comparison = switch (config.getAuthnContextComparisonType()) {
            case BETTER -> !responseSpidLevel.equals(config.getAuthnContextClassRefs()) ? spidLevelFromResponse : 0;
            case MAXIMUM -> spidLevelFromResponse > spidLevelFromConfig ? spidLevelFromResponse : 0;
            case MINIMUM -> spidLevelFromResponse < spidLevelFromConfig ? spidLevelFromResponse : 0;
            case EXACT -> spidLevelFromResponse != spidLevelFromConfig ? spidLevelFromResponse : 0;
        };

        //98,99,100,103,104,105,106,107,108 caught by kc
        //109 ok
        return switch (comparison) {
            case 1 -> "SpidSamlCheck_94";
            case 2 -> "SpidSamlCheck_95";
            case 3 -> "SpidSamlCheck_96";
            default -> null;
        };

    }

    private int extractSpidLevel(String value) {
        return switch (value) {
            case "https://www.spid.gov.it/SpidL1" -> 1;
            case "https://www.spid.gov.it/SpidL2" -> 2;
            case "https://www.spid.gov.it/SpidL3" -> 3;
            default -> 0;
        };
    }

    private Element getDocumentElement(Element assertionElement, String subject) {
        return DocumentUtil.getChildElement(assertionElement,
                new QName(JBossSAMLURIConstants.ASSERTION_NSURI.get(), subject));
    }

    private boolean hasNamedChild(Element element) {
        NodeList childNodes = element.getChildNodes();
        if (childNodes == null) return false;

        for (int i = 0; i < childNodes.getLength(); ++i) {
            Node node = childNodes.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE && node.getNodeName() != null)
                return true;
        }

        return false;
    }

    public String checkSpidStatus(ResponseType responseType) {
        if (!isSuccessfulSamlResponse(responseType)) {
            // Translate SPID error codes to meaningful messages
            boolean isSpidFault = responseType.getStatus() != null && responseType.getStatus().getStatusMessage() != null && responseType.getStatus().getStatusMessage().startsWith("ErrorCode nr");
            if (isSpidFault) {
                return "SpidFault_" + responseType.getStatus().getStatusMessage().replace(' ', '_');
            } else {
                return responseType.getStatus() == null ? "SpidSamlCheck_23" : responseType.getStatus().getStatusMessage();
            }
        }
        return null;
    }

    private boolean isSuccessfulSamlResponse(ResponseType responseType) {
        return responseType != null
                && responseType.getStatus() != null
                && responseType.getStatus().getStatusCode() != null
                && responseType.getStatus().getStatusCode().getValue() != null
                && Objects.equals(responseType.getStatus().getStatusCode().getValue().toString(), JBossSAMLURIConstants.STATUS_SUCCESS.get());
    }

    // Validate InResponseTo attribute: must match the generated request ID
    public boolean validateInResponseToAttribute(ResponseType responseType, String expectedRequestId) {

        // If we are not expecting a request ID, don't bother
        if (expectedRequestId == null || expectedRequestId.isEmpty())
            return true;

        // We are expecting a request ID so we are in SP-initiated login, attribute InResponseTo must be present
        if (responseType.getInResponseTo() == null) {
            logger.error("Response Validation Error: InResponseTo attribute was expected but not present in received response");
            return false;
        }

        // Attribute is present, proceed with validation
        // 1) Attribute Response > InResponseTo must not be empty
        String responseInResponseToValue = responseType.getInResponseTo();
        if (responseInResponseToValue.isEmpty()) {
            logger.error("Response Validation Error: InResponseTo attribute was expected but it is empty in received response");
            return false;
        }

        // 2) Attribute Response > InResponseTo must match request ID
        if (!responseInResponseToValue.equals(expectedRequestId)) {
            logger.error("Response Validation Error: received InResponseTo attribute does not match the expected request ID");
            return false;
        }

        // If present, Assertion > Subject > Confirmation > SubjectConfirmationData > InResponseTo must also be validated
        if (responseType.getAssertions().isEmpty())
            return true;

        SubjectType subjectElement = responseType.getAssertions().get(0).getAssertion().getSubject();
        if (subjectElement != null) {
            if (subjectElement.getConfirmation() != null && !subjectElement.getConfirmation().isEmpty()) {
                SubjectConfirmationType subjectConfirmationElement = subjectElement.getConfirmation().get(0);

                if (subjectConfirmationElement != null) {
                    SubjectConfirmationDataType subjectConfirmationDataElement = subjectConfirmationElement.getSubjectConfirmationData();

                    if (subjectConfirmationDataElement != null) {
                        if (subjectConfirmationDataElement.getInResponseTo() != null) {
                            // 3) Assertion > Subject > Confirmation > SubjectConfirmationData > InResponseTo is empty
                            String subjectConfirmationDataInResponseToValue = subjectConfirmationDataElement.getInResponseTo();
                            if (subjectConfirmationDataInResponseToValue.isEmpty()) {
                                logger.error("Response Validation Error: SubjectConfirmationData InResponseTo attribute was expected but it is empty in received response");
                                return false;
                            }

                            // 4) Assertion > Subject > Confirmation > SubjectConfirmationData > InResponseTo does not match request ID
                            if (!subjectConfirmationDataInResponseToValue.equals(expectedRequestId)) {
                                logger.error("Response Validation Error: received SubjectConfirmationData InResponseTo attribute does not match the expected request ID");
                                return false;
                            }
                        }
                    }
                }
            }
        }

        return true;
    }

    public String checkAssertions(ResponseType responseType) {
        return responseType.getAssertions() == null || responseType.getAssertions().isEmpty() ? "SpidSamlCheck_32" : null;
    }
}
