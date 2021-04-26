package org.keycloak.broker.spid.metadata;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.XMLDSIG_NSURI;

// SPID-UPDATE Class added to implement buildKeyInfoElement(String keyName, String pemEncodedCertificate) static method, unavailable in SPMetadataDescriptor class of Keycloak v.9.0.3
// used by SpidSpMetadataResourceProvider class (code taken from keycloak v.12.0.0)
public class SpidSPMetadataDescriptor {

    public static Element buildKeyInfoElement(String keyName, String pemEncodedCertificate)
            throws javax.xml.parsers.ParserConfigurationException
    {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.newDocument();

        Element keyInfo = doc.createElementNS(XMLDSIG_NSURI.get(), "ds:KeyInfo");

        // SPID-UPDATE commented to avoid <ds:KeyName>... element that breaks validation
//        if (keyName != null) {
//            Element keyNameElement = doc.createElementNS(XMLDSIG_NSURI.get(), "ds:KeyName");
//            keyNameElement.setTextContent(keyName);
//            keyInfo.appendChild(keyNameElement);
//        }

        Element x509Data = doc.createElementNS(XMLDSIG_NSURI.get(), "ds:X509Data");

        Element x509Certificate = doc.createElementNS(XMLDSIG_NSURI.get(), "ds:X509Certificate");
        x509Certificate.setTextContent(pemEncodedCertificate);

        x509Data.appendChild(x509Certificate);

        keyInfo.appendChild(x509Data);

        return keyInfo;
    }
}
