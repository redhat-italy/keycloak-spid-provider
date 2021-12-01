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

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.spid.mappers.SamlProtocolExtension;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.VerificationException;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.AuthnStatementType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectConfirmationDataType;
import org.keycloak.dom.saml.v2.assertion.SubjectConfirmationType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.dom.saml.v2.protocol.*;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.protocol.saml.JaxrsSAML2BindingBuilder;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.SamlProtocolUtils;
import org.keycloak.protocol.saml.SamlService;
import org.keycloak.protocol.saml.SamlSessionUtils;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.saml.SAML2LogoutResponseBuilder;
import org.keycloak.saml.SAMLRequestParser;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StringUtil;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.keycloak.saml.processing.core.saml.v2.constants.X500SAMLProfileConstants;
import org.keycloak.saml.processing.core.saml.v2.util.AssertionUtil;
import org.keycloak.saml.processing.core.util.XMLSignatureUtil;
import org.keycloak.saml.processing.web.util.PostBindingUtil;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.PathParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import javax.xml.datatype.*;
import javax.xml.namespace.QName;
import java.io.IOException;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.keycloak.protocol.saml.SamlPrincipalType;
import org.keycloak.rotation.HardcodedKeyLocator;
import org.keycloak.rotation.KeyLocator;
import org.keycloak.saml.processing.core.util.KeycloakKeySamlExtensionGenerator;
import org.keycloak.saml.validators.ConditionsValidator;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.services.util.CacheControlUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.net.URI;
import java.security.cert.CertificateException;

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.crypto.dsig.XMLSignature;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class SpidSAMLEndpoint {
    protected static final Logger logger = Logger.getLogger(SpidSAMLEndpoint.class);
    public static final String SAML_FEDERATED_SESSION_INDEX = "SAML_FEDERATED_SESSION_INDEX";
    @Deprecated // in favor of SAML_FEDERATED_SUBJECT_NAMEID
    public static final String SAML_FEDERATED_SUBJECT = "SAML_FEDERATED_SUBJECT";
    @Deprecated // in favor of SAML_FEDERATED_SUBJECT_NAMEID
    public static final String SAML_FEDERATED_SUBJECT_NAMEFORMAT = "SAML_FEDERATED_SUBJECT_NAMEFORMAT";
    public static final String SAML_FEDERATED_SUBJECT_NAMEID = "SAML_FEDERATED_SUBJECT_NAME_ID";
    public static final String SAML_LOGIN_RESPONSE = "SAML_LOGIN_RESPONSE";
    public static final String SAML_ASSERTION = "SAML_ASSERTION";
    public static final String SAML_AUTHN_STATEMENT = "SAML_AUTHN_STATEMENT";
    public static final String ISSUER_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
    public static final String ASSERTION_NAMEID_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
    public static final String ASSERTION_ISSUER_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

    protected RealmModel realm;
    protected EventBuilder event;
    protected SpidIdentityProviderConfig config;
    protected IdentityProvider.AuthenticationCallback callback;
    protected SpidIdentityProvider provider;
    private final DestinationValidator destinationValidator;


    @Context
    private KeycloakSession session;

    @Context
    private ClientConnection clientConnection;

    @Context
    private HttpHeaders headers;


    public SpidSAMLEndpoint(RealmModel realm, SpidIdentityProvider provider, SpidIdentityProviderConfig config, IdentityProvider.AuthenticationCallback callback, DestinationValidator destinationValidator) {
        this.realm = realm;
        this.config = config;
        this.callback = callback;
        this.provider = provider;
        this.destinationValidator = destinationValidator;
    }

    @GET
    @NoCache
    @Path("descriptor")
    public Response getSPDescriptor() {
        return provider.export(session.getContext().getUri(), realm, null);
    }

    @GET
    public Response redirectBinding(@QueryParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
                                    @QueryParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
                                    @QueryParam(GeneralConstants.RELAY_STATE) String relayState)  {
        return new RedirectBinding().execute(samlRequest, samlResponse, relayState, null);
    }


    /**
     */
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response postBinding(@FormParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
                                @FormParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
                                @FormParam(GeneralConstants.RELAY_STATE) String relayState) {
        return new PostBinding().execute(samlRequest, samlResponse, relayState, null);
    }

    @Path("clients/{client_id}")
    @GET
    public Response redirectBinding(@QueryParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
                                    @QueryParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
                                    @QueryParam(GeneralConstants.RELAY_STATE) String relayState,
                                    @PathParam("client_id") String clientId)  {
        return new RedirectBinding().execute(samlRequest, samlResponse, relayState, clientId);
    }


    /**
     */
    @Path("clients/{client_id}")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response postBinding(@FormParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
                                @FormParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
                                @FormParam(GeneralConstants.RELAY_STATE) String relayState,
                                @PathParam("client_id") String clientId) {
        return new PostBinding().execute(samlRequest, samlResponse, relayState, clientId);
    }

    protected abstract class Binding {
        private boolean checkSsl() {
            if (session.getContext().getUri().getBaseUri().getScheme().equals("https")) {
                return true;
            } else {
                return !realm.getSslRequired().isRequired(clientConnection);
            }
        }

        protected Response basicChecks(String samlRequest, String samlResponse) {
            if (!checkSsl()) {
                event.event(EventType.LOGIN);
                event.error(Errors.SSL_REQUIRED);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.HTTPS_REQUIRED);
            }
            if (!realm.isEnabled()) {
                event.event(EventType.LOGIN_ERROR);
                event.error(Errors.REALM_DISABLED);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.REALM_NOT_ENABLED);
            }

            if (samlRequest == null && samlResponse == null) {
                event.event(EventType.LOGIN);
                event.error(Errors.INVALID_REQUEST);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);

            }
            return null;
        }

        protected abstract String getBindingType();
        protected abstract boolean containsUnencryptedSignature(SAMLDocumentHolder documentHolder);
        protected abstract void verifySignature(String key, SAMLDocumentHolder documentHolder) throws VerificationException;
        protected abstract SAMLDocumentHolder extractRequestDocument(String samlRequest);
        protected abstract SAMLDocumentHolder extractResponseDocument(String response);

        protected boolean isDestinationRequired() {
            return true;
        }

        protected KeyLocator getIDPKeyLocator() {
            List<Key> keys = new LinkedList<>();

            for (String signingCertificate : config.getSigningCertificates()) {
                X509Certificate cert = null;
                try {
                    cert = XMLSignatureUtil.getX509CertificateFromKeyInfoString(signingCertificate.replaceAll("\\s", ""));
                    cert.checkValidity();
                    keys.add(cert.getPublicKey());
                } catch (CertificateException e) {
                    logger.warnf("Ignoring invalid certificate: %s", cert);
                } catch (ProcessingException e) {
                    throw new RuntimeException(e);
                }
            }

            return new HardcodedKeyLocator(keys);
        }

        public Response execute(String samlRequest, String samlResponse, String relayState, String clientId) {
            event = new EventBuilder(realm, session, clientConnection);
            Response response = basicChecks(samlRequest, samlResponse);
            if (response != null) return response;
            if (samlRequest != null) return handleSamlRequest(samlRequest, relayState);
            else return handleSamlResponse(samlResponse, relayState, clientId);
        }

        protected Response handleSamlRequest(String samlRequest, String relayState) {
            SAMLDocumentHolder holder = extractRequestDocument(samlRequest);
            RequestAbstractType requestAbstractType = (RequestAbstractType) holder.getSamlObject();
            // validate destination
            if (isDestinationRequired() &&
                    requestAbstractType.getDestination() == null && containsUnencryptedSignature(holder)) {
                return getResponse(Errors.MISSING_REQUIRED_DESTINATION, Errors.INVALID_REQUEST, Messages.INVALID_REQUEST);
            }
            if (! destinationValidator.validate(getExpectedDestination(config.getAlias(), null), requestAbstractType.getDestination())) {
                return getResponse(Errors.INVALID_DESTINATION, Errors.INVALID_SAML_RESPONSE, Messages.INVALID_REQUEST);
            }
            if (config.isValidateSignature()) {
                try {
                    verifySignature(GeneralConstants.SAML_REQUEST_KEY, holder);
                } catch (VerificationException e) {
                    logger.error("validation failed", e);
                    event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                    event.error(Errors.INVALID_SIGNATURE);
                    return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUESTER);
                }
            }

            if (requestAbstractType instanceof LogoutRequestType) {
                logger.debug("** logout request");
                event.event(EventType.LOGOUT);
                LogoutRequestType logout = (LogoutRequestType) requestAbstractType;
                return logoutRequest(logout, relayState);

            } else {
                event.event(EventType.LOGIN);
                event.error(Errors.INVALID_TOKEN);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
            }
        }

        protected Response logoutRequest(LogoutRequestType request, String relayState) {
            String brokerUserId = config.getAlias() + "." + request.getNameID().getValue();
            if (request.getSessionIndex() == null || request.getSessionIndex().isEmpty()) {
                AtomicReference<LogoutRequestType> ref = new AtomicReference<>(request);
                session.sessions().getUserSessionByBrokerUserIdStream(realm, brokerUserId)
                        .filter(userSession -> userSession.getState() != UserSessionModel.State.LOGGING_OUT &&
                                userSession.getState() != UserSessionModel.State.LOGGED_OUT)
                        .collect(Collectors.toList()) // collect to avoid concurrent modification as backchannelLogout removes the user sessions.
                        .forEach(processLogout(ref));
                request = ref.get();

            }  else {
                for (String sessionIndex : request.getSessionIndex()) {
                    String brokerSessionId = config.getAlias()  + "." + sessionIndex;
                    UserSessionModel userSession = session.sessions().getUserSessionByBrokerSessionId(realm, brokerSessionId);
                    if (userSession != null) {
                        if (userSession.getState() == UserSessionModel.State.LOGGING_OUT || userSession.getState() == UserSessionModel.State.LOGGED_OUT) {
                            continue;
                        }

                        for(Iterator<SamlAuthenticationPreprocessor> it = SamlSessionUtils.getSamlAuthenticationPreprocessorIterator(session); it.hasNext();) {
                            request = it.next().beforeProcessingLogoutRequest(request, userSession, null);
                        }

                        try {
                            AuthenticationManager.backchannelLogout(session, realm, userSession, session.getContext().getUri(), clientConnection, headers, false);
                        } catch (Exception e) {
                            logger.warn("failed to do backchannel logout for userSession", e);
                        }
                    }
                }
            }

            String issuerURL = getEntityId(session.getContext().getUri(), realm);
            SAML2LogoutResponseBuilder builder = new SAML2LogoutResponseBuilder();
            builder.logoutRequestID(request.getID());
            builder.destination(config.getSingleLogoutServiceUrl());
            builder.issuer(issuerURL);
            JaxrsSAML2BindingBuilder binding = new JaxrsSAML2BindingBuilder(session)
                        .relayState(relayState);
            boolean postBinding = config.isPostBindingLogout();
            if (config.isWantAuthnRequestsSigned()) {
                KeyManager.ActiveRsaKey keys = session.keys().getActiveRsaKey(realm);
                String keyName = config.getXmlSigKeyInfoKeyNameTransformer().getKeyName(keys.getKid(), keys.getCertificate());
                binding.signWith(keyName, keys.getPrivateKey(), keys.getPublicKey(), keys.getCertificate())
                        .signatureAlgorithm(provider.getSignatureAlgorithm())
                        .signDocument();
                if (! postBinding && config.isAddExtensionsElementWithKeyInfo()) {    // Only include extension if REDIRECT binding and signing whole SAML protocol message
                    builder.addExtension(new KeycloakKeySamlExtensionGenerator(keyName));
                }
            }
            try {
                if (postBinding) {
                    return binding.postBinding(builder.buildDocument()).response(config.getSingleLogoutServiceUrl());
                } else {
                    return binding.redirectBinding(builder.buildDocument()).response(config.getSingleLogoutServiceUrl());
                }
            } catch (ConfigurationException e) {
                throw new RuntimeException(e);
            } catch (ProcessingException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

        }

        private Consumer<UserSessionModel> processLogout(AtomicReference<LogoutRequestType> ref) {
            return userSession -> {
                for(Iterator<SamlAuthenticationPreprocessor> it = SamlSessionUtils.getSamlAuthenticationPreprocessorIterator(session); it.hasNext();) {
                    ref.set(it.next().beforeProcessingLogoutRequest(ref.get(), userSession, null));
                }
                try {
                    AuthenticationManager.backchannelLogout(session, realm, userSession, session.getContext().getUri(), clientConnection, headers, false);
                } catch (Exception e) {
                    logger.warn("failed to do backchannel logout for userSession", e);
                }
            };
        }

        private String getEntityId(UriInfo uriInfo, RealmModel realm) {
            String configEntityId = config.getEntityId();

            if (configEntityId == null || configEntityId.isEmpty())
                return UriBuilder.fromUri(uriInfo.getBaseUri()).path("realms").path(realm.getName()).build().toString();
            else
                return configEntityId;
        }

        protected Response handleLoginResponse(String samlResponse, SAMLDocumentHolder holder, ResponseType responseType, String relayState, String clientId) {

            try {
                AuthenticationSessionModel authSession = getAuthenticationSessionModel(relayState, clientId);
                session.getContext().setAuthenticationSession(authSession);

                KeyManager.ActiveRsaKey keys = session.keys().getActiveRsaKey(realm);

                // questo blocco impedisce la definizione granulare dei messaggi

//                if (! isSuccessfulSamlResponse(responseType)) {
//                    // Translate SPID error codes to meaningful messages
//                    boolean isSpidFault = responseType.getStatus() != null
//                        && responseType.getStatus().getStatusMessage() != null
//                        && responseType.getStatus().getStatusMessage().startsWith("ErrorCode nr");
//                    if (isSpidFault)
//                        return callback.error("SpidFault_" + responseType.getStatus().getStatusMessage().replace(' ', '_'));
                    // questo blocco impedisce la definizione granulare dei messaggi
//                    else
//                    {

//                        String statusMessage = responseType.getStatus() == null ? Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR : responseType.getStatus().getStatusMessage();
//                        return callback.error(statusMessage);
//                    }
//                }
                if (responseType.getAssertions() == null || responseType.getAssertions().isEmpty()) {
                    return callback.error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }

                boolean assertionIsEncrypted = AssertionUtil.isAssertionEncrypted(responseType);

                if (config.isWantAssertionsEncrypted() && !assertionIsEncrypted) {
                    logger.error("The assertion is not encrypted, which is required.");
                    event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                    event.error(Errors.INVALID_SAML_RESPONSE);
                    return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.INVALID_REQUESTER);
                }

                Element assertionElement;

                if (assertionIsEncrypted) {
                    // This methods writes the parsed and decrypted assertion back on the responseType parameter:
                    assertionElement = AssertionUtil.decryptAssertion(holder, responseType, keys.getPrivateKey());
                } else {
                    /* We verify the assertion using original document to handle cases where the IdP
                    includes whitespace and/or newlines inside tags. */
                    assertionElement = DocumentUtil.getElement(holder.getSamlDocument(), new QName(JBossSAMLConstants.ASSERTION.get()));
                }

                // Apply SPID-specific response validation rules
                String spidExpectedRequestId = authSession.getClientNote(SamlProtocolExtension.SAML_REQUEST_ID_BROKER);
                String spidResponseValidationError = verifySpidResponse(holder.getSamlDocument().getDocumentElement(),
                        assertionElement,
                        spidExpectedRequestId,
                        responseType,
                        authSession);

                if (spidResponseValidationError != null)
                {
                    logger.error("SPID Response Validation Error: " + spidResponseValidationError);
                    event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                    event.error(Errors.INVALID_SAML_RESPONSE);
                    return callback.error(spidResponseValidationError);
                }

                // Validate InResponseTo attribute: must match the generated request ID
                String expectedRequestId = authSession.getClientNote(SamlProtocolExtension.SAML_REQUEST_ID_BROKER);
                final boolean inResponseToValidationSuccess = validateInResponseToAttribute(responseType, expectedRequestId);
                if (!inResponseToValidationSuccess)
                {
                    event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                    event.error(Errors.INVALID_SAML_RESPONSE);
                    return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.INVALID_REQUESTER);
                }

                boolean signed = AssertionUtil.isSignedElement(assertionElement);
                final boolean assertionSignatureNotExistsWhenRequired = config.isWantAssertionsSigned() && !signed;
                final boolean signatureNotValid = signed && config.isValidateSignature() && !AssertionUtil.isSignatureValid(assertionElement, getIDPKeyLocator());
                final boolean hasNoSignatureWhenRequired = ! signed && config.isValidateSignature() && ! containsUnencryptedSignature(holder);

                if (assertionSignatureNotExistsWhenRequired || signatureNotValid || hasNoSignatureWhenRequired) {
                    logger.error("validation failed");
                    event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                    event.error(Errors.INVALID_SIGNATURE);
                    return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.INVALID_REQUESTER);
                }

                AssertionType assertion = responseType.getAssertions().get(0).getAssertion();
                NameIDType subjectNameID = getSubjectNameID(assertion);
                String principal = getPrincipal(assertion);

                if (principal == null) {
                    logger.errorf("no principal in assertion; expected: %s", expectedPrincipalType());
                    event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                    event.error(Errors.INVALID_SAML_RESPONSE);
                    return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.INVALID_REQUESTER);
                }

                //Map<String, String> notes = new HashMap<>();
                BrokeredIdentityContext identity = new BrokeredIdentityContext(principal);
                identity.getContextData().put(SAML_LOGIN_RESPONSE, responseType);
                identity.getContextData().put(SAML_ASSERTION, assertion);
                identity.setAuthenticationSession(authSession);

                identity.setUsername(principal);

                //SAML Spec 2.2.2 Format is optional
                if (subjectNameID != null && subjectNameID.getFormat() != null && subjectNameID.getFormat().toString().equals(JBossSAMLURIConstants.NAMEID_FORMAT_EMAIL.get())) {
                    identity.setEmail(subjectNameID.getValue());
                }

                if (config.isStoreToken()) {
                    identity.setToken(samlResponse);
                }

                ConditionsValidator.Builder cvb = new ConditionsValidator.Builder(assertion.getID(), assertion.getConditions(), destinationValidator)
                        .clockSkewInMillis(1000 * config.getAllowedClockSkew());
                try {
                    String issuerURL = getEntityId(session.getContext().getUri(), realm);
                    cvb.addAllowedAudience(URI.create(issuerURL));
                    // getDestination has been validated to match request URL already so it matches SAML endpoint
                    if (responseType.getDestination() != null) {
                        cvb.addAllowedAudience(URI.create(responseType.getDestination()));
                    }
                } catch (IllegalArgumentException ex) {
                    // warning has been already emitted in DeploymentBuilder
                }
                if (! cvb.build().isValid()) {
                    logger.error("Assertion expired.");
                    event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                    event.error(Errors.INVALID_SAML_RESPONSE);
                    return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, Messages.EXPIRED_CODE);
                }

                AuthnStatementType authn = null;
                for (Object statement : assertion.getStatements()) {
                    if (statement instanceof AuthnStatementType) {
                        authn = (AuthnStatementType)statement;
                        identity.getContextData().put(SAML_AUTHN_STATEMENT, authn);
                        break;
                    }
                }
                if (assertion.getAttributeStatements() != null ) {
                    String email = getX500Attribute(assertion, X500SAMLProfileConstants.EMAIL);
                    if (email != null)
                        identity.setEmail(email);
                }

                String brokerUserId = config.getAlias() + "." + principal;
                identity.setBrokerUserId(brokerUserId);
                identity.setIdpConfig(config);
                identity.setIdp(provider);
                if (authn != null && authn.getSessionIndex() != null) {
                    identity.setBrokerSessionId(config.getAlias() + "." + authn.getSessionIndex());
                 }


                return callback.authenticated(identity);
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (Exception e) {
                throw new IdentityBrokerException("Could not process response from SAML identity provider.", e);
            }
        }

        private AuthenticationSessionModel getAuthenticationSessionModel(String relayState, String clientId) {
            AuthenticationSessionModel authSession;
            if (clientId != null && ! clientId.trim().isEmpty()) {
                authSession = samlIdpInitiatedSSO(clientId);
            } else {
                authSession = callback.getAndVerifyAuthenticationSession(relayState);
            }
            return authSession;
        }


        /**
         * If there is a client whose SAML IDP-initiated SSO URL name is set to the
         * given {@code clientUrlName}, creates a fresh authentication session for that
         * client and returns a {@link AuthenticationSessionModel} object with that session.
         * Otherwise returns "client not found" response.
         *
         * @param clientUrlName
         * @return see description
         */
        private AuthenticationSessionModel samlIdpInitiatedSSO(final String clientUrlName) {
            event.event(EventType.LOGIN);
            CacheControlUtil.noBackButtonCacheControlHeader();
            Optional<ClientModel> oClient = SpidSAMLEndpoint.this.session.clients()
              .searchClientsByAttributes(realm, Collections.singletonMap(SamlProtocol.SAML_IDP_INITIATED_SSO_URL_NAME, clientUrlName), 0, 1)
              .findFirst();

            if (! oClient.isPresent()) {
                event.error(Errors.CLIENT_NOT_FOUND);
                Response response = ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.CLIENT_NOT_FOUND);
                throw new WebApplicationException(response);
            }

            LoginProtocolFactory factory = (LoginProtocolFactory) session.getKeycloakSessionFactory().getProviderFactory(LoginProtocol.class, SamlProtocol.LOGIN_PROTOCOL);
            SamlService samlService = (SamlService) factory.createProtocolEndpoint(SpidSAMLEndpoint.this.realm, event);
            ResteasyProviderFactory.getInstance().injectProperties(samlService);
            AuthenticationSessionModel authSession = samlService.getOrCreateLoginSessionForIdpInitiatedSso(session, SpidSAMLEndpoint.this.realm, oClient.get(), null);
            if (authSession == null) {
                event.error(Errors.INVALID_REDIRECT_URI);
                Response response = ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REDIRECT_URI);
                throw new WebApplicationException(response);
            }

            return authSession;
        }


        private boolean isSuccessfulSamlResponse(ResponseType responseType) {
            return responseType != null
              && responseType.getStatus() != null
              && responseType.getStatus().getStatusCode() != null
              && responseType.getStatus().getStatusCode().getValue() != null
              && Objects.equals(responseType.getStatus().getStatusCode().getValue().toString(), JBossSAMLURIConstants.STATUS_SUCCESS.get());
        }


        public Response handleSamlResponse(String samlResponse, String relayState, String clientId) {
            SAMLDocumentHolder holder = extractResponseDocument(samlResponse);
            if (holder == null) {
                // ADDED AUTH SESSION SET
                AuthenticationSessionModel authSession = getAuthenticationSessionModel(relayState, clientId);
                session.getContext().setAuthenticationSession(authSession);

                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.detail(Details.REASON, Errors.INVALID_SAML_DOCUMENT);
                event.error(Errors.INVALID_SAML_RESPONSE);
                return callback.error("SpidSamlCheck_GenericResponseParsingError");

                // ORIGINAL BEHAVIOUR
                // return getResponse(Errors.INVALID_SAML_DOCUMENT, Errors.INVALID_SAML_RESPONSE, Messages.INVALID_FEDERATED_IDENTITY_ACTION);
            }
            StatusResponseType statusResponse = (StatusResponseType)holder.getSamlObject();


            // validate destination
            if (isDestinationRequired()
                    && statusResponse.getDestination() == null && containsUnencryptedSignature(holder)) {
                // ADDED AUTH SESSION SET
                AuthenticationSessionModel authSession = getAuthenticationSessionModel(relayState, clientId);
                session.getContext().setAuthenticationSession(authSession);

                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.detail(Details.REASON, Errors.MISSING_REQUIRED_DESTINATION);
                event.error(Errors.INVALID_SAML_LOGOUT_RESPONSE);
                return callback.error("SpidSamlCheck_GenericResponseParsingError");

                // ORIGINAL BEHAVIOUR
                //  return getResponse(Errors.MISSING_REQUIRED_DESTINATION, Errors.INVALID_SAML_LOGOUT_RESPONSE, Messages.INVALID_REQUEST);
            }

            if (! destinationValidator.validate(getExpectedDestination(config.getAlias(), clientId), statusResponse.getDestination())) {
                // ADDED AUTH SESSION SET
                AuthenticationSessionModel authSession = getAuthenticationSessionModel(relayState, clientId);
                session.getContext().setAuthenticationSession(authSession);

                event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                event.detail(Details.REASON, Errors.INVALID_DESTINATION);
                event.error(Errors.INVALID_SAML_RESPONSE);
                return callback.error("SpidSamlCheck_GenericResponseParsingError");

                // ORIGINAL BEHAVIOUR
                // return getResponse(Errors.INVALID_DESTINATION, Errors.INVALID_SAML_RESPONSE, Messages.INVALID_REQUEST);
            }
            if (config.isValidateSignature()) {
                try {
                    verifySignature(GeneralConstants.SAML_RESPONSE_KEY, holder);
                } catch (VerificationException e) {
                    // ADDED AUTH SESSION SET
                    AuthenticationSessionModel authSession = getAuthenticationSessionModel(relayState, clientId);
                    session.getContext().setAuthenticationSession(authSession);

                    logger.error("validation failed", e);
                    event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
                    event.error(Errors.INVALID_SIGNATURE);
                    return callback.error("SpidSamlCheck_04");

                    // ORIGINAL BEHAVIOUR
                    // return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_FEDERATED_IDENTITY_ACTION);
                }
            }
            if (statusResponse instanceof ResponseType) {
                return handleLoginResponse(samlResponse, holder, (ResponseType)statusResponse, relayState, clientId);

            } else {
                // todo need to check that it is actually a LogoutResponse
                return handleLogoutResponse(holder, statusResponse, relayState);
            }
            //throw new RuntimeException("Unknown response type");

        }

        protected Response handleLogoutResponse(SAMLDocumentHolder holder, StatusResponseType responseType, String relayState) {
            if (relayState == null) {
                logger.error("no valid user session");
                event.event(EventType.LOGOUT);
                event.error(Errors.USER_SESSION_NOT_FOUND);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }
            UserSessionModel userSession = session.sessions().getUserSession(realm, relayState);
            if (userSession == null) {
                logger.error("no valid user session");
                event.event(EventType.LOGOUT);
                event.error(Errors.USER_SESSION_NOT_FOUND);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }
            if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
                logger.error("usersession in different state");
                event.event(EventType.LOGOUT);
                event.error(Errors.USER_SESSION_NOT_FOUND);
                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.SESSION_NOT_ACTIVE);
            }
            return AuthenticationManager.finishBrowserLogout(session, realm, userSession, session.getContext().getUri(), clientConnection, headers);
        }

        private String getExpectedDestination(String providerAlias, String clientId) {
            if(clientId != null) {
                return session.getContext().getUri().getAbsolutePath().toString();
            }
            return Urls.identityProviderAuthnResponse(session.getContext().getUri().getBaseUri(), providerAlias, realm.getName()).toString();
        }
    }

    private Response getResponse(String invalidReason, String invalidSamlResponse, String errorDisplayed) {
        event.event(EventType.IDENTITY_PROVIDER_RESPONSE);
        event.detail(Details.REASON, invalidReason);
        event.error(invalidSamlResponse);
        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, errorDisplayed);
    }

    protected class PostBinding extends Binding {
        @Override
        protected boolean containsUnencryptedSignature(SAMLDocumentHolder documentHolder) {
            NodeList nl = documentHolder.getSamlDocument().getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            return (nl != null && nl.getLength() > 0);
        }

        @Override
        protected void verifySignature(String key, SAMLDocumentHolder documentHolder) throws VerificationException {
            if ((! containsUnencryptedSignature(documentHolder)) && (documentHolder.getSamlObject() instanceof ResponseType)) {
                ResponseType responseType = (ResponseType) documentHolder.getSamlObject();
                List<ResponseType.RTChoiceType> assertions = responseType.getAssertions();
                if (! assertions.isEmpty() ) {
                    // Only relax verification if the response is an authnresponse and contains (encrypted/plaintext) assertion.
                    // In that case, signature is validated on assertion element
                    return;
                }
            }
            SamlProtocolUtils.verifyDocumentSignature(documentHolder.getSamlDocument(), getIDPKeyLocator());
        }

        @Override
        protected SAMLDocumentHolder extractRequestDocument(String samlRequest) {
            return SAMLRequestParser.parseRequestPostBinding(samlRequest);
        }
        @Override
        protected SAMLDocumentHolder extractResponseDocument(String response) {
            byte[] samlBytes = PostBindingUtil.base64Decode(response);
            return SAMLRequestParser.parseResponseDocument(samlBytes);
        }

        @Override
        protected String getBindingType() {
            return SamlProtocol.SAML_POST_BINDING;
        }
    }

    protected class RedirectBinding extends Binding {
        @Override
        protected boolean containsUnencryptedSignature(SAMLDocumentHolder documentHolder) {
            MultivaluedMap<String, String> encodedParams = session.getContext().getUri().getQueryParameters(false);
            String algorithm = encodedParams.getFirst(GeneralConstants.SAML_SIG_ALG_REQUEST_KEY);
            String signature = encodedParams.getFirst(GeneralConstants.SAML_SIGNATURE_REQUEST_KEY);
            return algorithm != null && signature != null;
        }

        @Override
        protected void verifySignature(String key, SAMLDocumentHolder documentHolder) throws VerificationException {
            KeyLocator locator = getIDPKeyLocator();
            SamlProtocolUtils.verifyRedirectSignature(documentHolder, locator, session.getContext().getUri(), key);
        }



        @Override
        protected SAMLDocumentHolder extractRequestDocument(String samlRequest) {
            return SAMLRequestParser.parseRequestRedirectBinding(samlRequest);
        }

        @Override
        protected SAMLDocumentHolder extractResponseDocument(String response) {
            return SAMLRequestParser.parseResponseRedirectBinding(response);
        }

        @Override
        protected String getBindingType() {
            return SamlProtocol.SAML_REDIRECT_BINDING;
        }

    }

    private String getX500Attribute(AssertionType assertion, X500SAMLProfileConstants attribute) {
        return getFirstMatchingAttribute(assertion, attribute::correspondsTo);
    }

    private String getAttributeByName(AssertionType assertion, String name) {
        return getFirstMatchingAttribute(assertion, attribute -> Objects.equals(attribute.getName(), name));
    }

    private String getAttributeByFriendlyName(AssertionType assertion, String friendlyName) {
        return getFirstMatchingAttribute(assertion, attribute -> Objects.equals(attribute.getFriendlyName(), friendlyName));
    }

    private String getPrincipal(AssertionType assertion) {

        SamlPrincipalType principalType = config.getPrincipalType();

        if (principalType == null || principalType.equals(SamlPrincipalType.SUBJECT)) {
            NameIDType subjectNameID = getSubjectNameID(assertion);
            return subjectNameID != null ? subjectNameID.getValue() : null;
        } else if (principalType.equals(SamlPrincipalType.ATTRIBUTE)) {
            return getAttributeByName(assertion, config.getPrincipalAttribute());
        } else {
            return getAttributeByFriendlyName(assertion, config.getPrincipalAttribute());
        }

    }

    private String getFirstMatchingAttribute(AssertionType assertion, Predicate<AttributeType> predicate) {
        return assertion.getAttributeStatements().stream()
                .map(AttributeStatementType::getAttributes)
                .flatMap(Collection::stream)
                .map(AttributeStatementType.ASTChoiceType::getAttribute)
                .filter(predicate)
                .map(AttributeType::getAttributeValue)
                .flatMap(Collection::stream)
                .findFirst()
                .map(Object::toString)
                .orElse(null);
    }

    private String expectedPrincipalType() {
        SamlPrincipalType principalType = config.getPrincipalType();
        switch (principalType) {
            case SUBJECT:
                return principalType.name();
            case ATTRIBUTE:
            case FRIENDLY_ATTRIBUTE:
                return String.format("%s(%s)", principalType.name(), config.getPrincipalAttribute());
            default:
                return null;
        }
    }

    private NameIDType getSubjectNameID(final AssertionType assertion) {
        SubjectType subject = assertion.getSubject();
        SubjectType.STSubType subType = subject.getSubType();
        return subType != null ? (NameIDType) subType.getBaseID() : null;
    }

    private boolean validateInResponseToAttribute(ResponseType responseType, String expectedRequestId) {
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
            if (subjectElement.getConfirmation() != null && !subjectElement.getConfirmation().isEmpty())
            {
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

    /**
     * This method verifies the correctness of the response sent by the IdP.
     * The comments written in italian are the actual copy of the error statements
     * given by the AGID testing tool. In this way it is possible to keep track which code block
     * belongs to which test, and its requirement.
     *
     * @param documentElement
     * @param assertionElement
     * @param expectedRequestId
     * @param responseType
     * @param authSession
     * @return spidcode response error string
     */
    private String verifySpidResponse(Element documentElement,
                                      Element assertionElement,
                                      String expectedRequestId,
                                      ResponseType responseType,
                                      AuthenticationSessionModel authSession)
    {
            //2: Unsigned Response
           if (responseType.getSignature() == null) {
                return "SpidSamlCheck_02";
            }

            //3: Unsigned Assertion
            if (responseType.getAssertions().size() > 0 &&
                    responseType.getAssertions().get(0).getAssertion().getSignature() == null) {
                return "SpidSamlCheck_03";
            }
            //8: Null ID
            if (StringUtil.isNullOrEmpty(responseType.getID())) {
                return "SpidSamlCheck_08";
            }


        String requestIssueInstantNote = authSession.getClientNote(JBossSAMLConstants.ISSUE_INSTANT.name());
        try {
            XMLGregorianCalendar requestIssueInstant = DatatypeFactory.newInstance().
                    newXMLGregorianCalendar(requestIssueInstantNote);

            // 13: IssueInstant correct UTC format -> non valid UTC format throws DateTimeParseException
            Instant.parse(responseType.getIssueInstant().toString());


            XMLGregorianCalendar responseIssueInstant = responseType.getIssueInstant();

            //14: Issue Instant req < Issue Instant Response
            if(responseIssueInstant.compare(requestIssueInstant) != DatatypeConstants.GREATER){
                return "SpidSamlCheck_14";
            }

            //15: Response Attribute IssueInstant within three minutes of request IssueInstant
            //https://github.com/italia/spid-saml-check/issues/73
            //max tolerance of three minutes
            long responseTimeMillis = responseIssueInstant.toGregorianCalendar().getTimeInMillis();
            long requestTimeMillis = requestIssueInstant.toGregorianCalendar().getTimeInMillis();

            if((responseTimeMillis-requestTimeMillis)>0 && (responseTimeMillis-requestTimeMillis)>180000){
                return "SpidSamlCheck_15";

            }


            GregorianCalendar now = new GregorianCalendar();
            XMLGregorianCalendar nowXmlGregorianCalendar = DatatypeFactory.newInstance().newXMLGregorianCalendar(now);
            if(responseIssueInstant.compare(nowXmlGregorianCalendar) == DatatypeConstants.GREATER){
                return "SpidSamlCheck_15";
            }

            //110 IssueInstant must not have milliseconds
            int responseIssueInstantMillisecond = responseIssueInstant.getMillisecond();
            if(responseIssueInstantMillisecond>0){
                return "SpidSamlCheck_110";
            }


        } catch (DatatypeConfigurationException e) {
            logger.error("Could not convert request IssueInstant to XMLGregorianCalendar, wrong format?");
            return "SpidFault_ErrorCode_nr3";
        } catch (DateTimeParseException e){
            return "SpidSamlCheck_13";
        }

        // 17: Response > InResponseTo missing
             if (!documentElement.hasAttribute("InResponseTo")) {
            return "SpidSamlCheck_nr17";
        }

        // 16: Response > InResponseTo empty
        String responseInResponseToValue = documentElement.getAttribute("InResponseTo");
        if (responseInResponseToValue.isEmpty()) {
            return "SpidSamlCheck_nr16";
        }

        // 18: Response > InResponseTo does not match request ID
        if (!responseInResponseToValue.equals(expectedRequestId)) {
            return "SpidSamlCheck_nr18";
        }

        //22 Unspecified Element Status
        if(responseType.getStatus()!=null &&
                responseType.getStatus().getStatusCode()==null &&
                responseType.getStatus().getStatusDetail()==null &&
                responseType.getStatus().getStatusMessage() == null){
            return "SpidSamlCheck_22";
        }

        //23 Missing Element Status
        if(responseType.getStatus()==null){
            return "SpidSamlCheck_23";
        }

        //24 Unspecified Element StatusCode
        if(responseType.getStatus()!=null &&
                responseType.getStatus().getStatusCode()!=null &&
                StringUtil.isNullOrEmpty(responseType.getStatus().getStatusCode().getValue().toString())){
            return "SpidSamlCheck_24";
        }

        //25 Missing StatusCode: note-> The test fails with code 22 because the
        // element <samlp:Status\> sent by the response is the same. (See response  xml from the SPID testing tool)

        if(responseType.getStatus()!=null &&
                responseType.getStatus().getStatusCode()==null){
            return "SpidSamlCheck_25";
        }

        //26 StatusCode element != Success
        if(responseType.getStatus()!=null &&
                responseType.getStatus().getStatusCode()!=null &&
                !responseType.getStatus().getStatusCode().getValue().toString().substring(responseType.getStatus().getStatusCode().getValue().toString().lastIndexOf(":")+1).equals("Success")){
            return "SpidSamlCheck_26";
        }

        //27 Unspecified Issuer element
        if(responseType.getIssuer()!=null &&
                StringUtil.isNullOrEmpty(responseType.getIssuer().getValue())){
            return "SpidSamlCheck_27";
        }

        //28 Missing element Issuer
        // the test fails with code 1 (test2) because the testing tool sends an unsigned response
        // the control block is included anyhow
        if(responseType.getIssuer()==null){
            return "SpidSamlCheck_28";
        }

        //29 Element Issuer != EntityID IdP
        if(!responseType.getIssuer().getValue().equalsIgnoreCase(config.getIdpEntityId())){
            return "SpidSamlCheck_29";
        }

        //30/31  Format di Issuer attribute must be omitted or have the value  urn:oasis:names:tc:SAML:2.0:nameid-format:entity
        if(responseType.getIssuer()!=null &&
            responseType.getIssuer().getFormat()!=null &&
            !responseType.getIssuer().getFormat().toString().equals(ISSUER_FORMAT)){
            return "SpidSamlCheck_30";
        }

        //33 Assertion attribute ID unspecified
        //32/34 checked by keycloak
        String assertionID = assertionElement.getAttribute("ID");
        if(assertionID.equals("")){
            return "SpidSamlCheck_33";
        }

        String assertionIssueInstant = assertionElement.getAttribute("IssueInstant");


        if(!StringUtil.isNullOrEmpty(assertionIssueInstant)){
            try {
                XMLGregorianCalendar requestIssueInstant = DatatypeFactory.newInstance().
                        newXMLGregorianCalendar(requestIssueInstantNote);
                XMLGregorianCalendar assertionIssueInstantXML = DatatypeFactory.newInstance().
                        newXMLGregorianCalendar(assertionIssueInstant);
                //39 Assertion IssueInstant attribute < Request IssueInstant

                if(assertionIssueInstantXML.compare(requestIssueInstant) == DatatypeConstants.LESSER){
                    return "SpidSamlCheck_39";
                }

                //40. Assertion IssueInstant attribute > later than 3 minutes from request
                //https://github.com/italia/spid-saml-check/issues/73
                //max tolerance of three minutes
                long assertionTimeMillis = assertionIssueInstantXML.toGregorianCalendar().getTimeInMillis();
                long requestTimemillis = requestIssueInstant.toGregorianCalendar().getTimeInMillis();

                if((assertionTimeMillis-requestTimemillis)>0 && (assertionTimeMillis-requestTimemillis)>180000){
                    return "SpidSamlCheck_40";

                }

                //110 Assertion IssueInstant with milliseconds
                int assertionIssueInstantXMLMillisecond = assertionIssueInstantXML.getMillisecond();
                if (assertionIssueInstantXMLMillisecond > 0){
                    return "SpidSamlCheck_110";
                }

            } catch (DatatypeConfigurationException e) {
                logger.error("Could not convert request IssueInstant to XMLGregorianCalendar, wrong format?");
                return "SpidFault_ErrorCode_nr3";
            }
        }

        // 42: Assertion > Subject missing
        Element subjectElement = getDocumentElement(assertionElement, "Subject");
        if (subjectElement == null) {
            return "SpidSamlCheck_nr42";
        }

        // 41: Assertion > Subject empty (Keycloak returns error earlier)
        if (!hasNamedChild(subjectElement)) {
            return "SpidSamlCheck_nr41";
        }

        //44 Assertion NameID missing
        Element nameID = getDocumentElement(assertionElement, "NameID");
        if(nameID==null){
                return "SpidSamlCheck_44";
        }

        //43 Assertion NameID unspecified
        if(nameID.getFirstChild() != null && StringUtil.isNullOrEmpty(nameID.getFirstChild().getNodeValue().trim())){
        return "SpidSamlCheck_43";
       }

        //45/46 Format NameID attribute missing or unspecified
        if(StringUtil.isNullOrEmpty(nameID.getAttribute("Format"))){
            return "SpidSamlCheck_4546";
        }

        //47 Format NameID attribute !=  urn:oasis:names:tc:SAML:2.0:nameidformat:transient
        if(!StringUtil.isNullOrEmpty(nameID.getAttribute("Format")) && !nameID.getAttribute("Format").equals(ASSERTION_NAMEID_FORMAT)){
            return "SpidSamlCheck_47";

        }
        //48/49 Assertion NameQualifier unspecified
        if(StringUtil.isNullOrEmpty(nameID.getAttribute("NameQualifier"))){
            return "SpidSamlCheck_4849";
        }

        // 52: Assertion > Subject > Confirmation missing
        Element subjectConfirmationElement = getDocumentElement(subjectElement, "SubjectConfirmation");

        if (subjectConfirmationElement == null) {
            return "SpidSamlCheck_nr52";
        }

        // 51: Assertion > Subject > Confirmation empty
        if (!hasNamedChild(subjectConfirmationElement)) {
            return "SpidSamlCheck_nr51";
        }

        // 53: Assertion > Subject > Confirmation > Method missing
        if (!subjectConfirmationElement.hasAttribute("Method")) {
            return "SpidSamlCheck_nr54";
        }

        // 54: Assertion > Subject > Confirmation > Method empty
        String subjectConfirmationMethodValue = subjectConfirmationElement.getAttribute("Method");
        if (subjectConfirmationMethodValue.isEmpty()) {
            return "SpidSamlCheck_nr53";
        }

        // 55: Assertion > Subject > Confirmation > Method is not JBossSAMLURIConstants.SUBJECT_CONFIRMATION_BEARER
        if (!subjectConfirmationMethodValue.equals(JBossSAMLURIConstants.SUBJECT_CONFIRMATION_BEARER.get())) {
            return "SpidSamlCheck_nr55";
        }

        // 56: Assertion > Subject > Confirmation > SubjectConfirmationData missing. Testing tool xml snippet same as 51
        Element subjectConfirmationDataElement = getDocumentElement(subjectConfirmationElement, "SubjectConfirmationData");

        if (subjectConfirmationDataElement == null) {
            return "SpidSamlCheck_nr56";
        }

        // 58: Assertion > Subject > Confirmation > SubjectConfirmationData > Recipient missing
        if (!subjectConfirmationDataElement.hasAttribute("Recipient")) {
            return "SpidSamlCheck_nr58";
        }

        // 59: Assertion > Subject > Confirmation > SubjectConfirmationData > different than AssertionConsumerServiceURL
        String assertionConsumerServiceURL = authSession.getClientNote(JBossSAMLConstants.ASSERTION_CONSUMER_SERVICE_URL.name());
        String recipient = subjectConfirmationDataElement.getAttribute("Recipient");
        if(!StringUtil.isNullOrEmpty(recipient) && !recipient.trim().equals(assertionConsumerServiceURL.trim())){
                return "SpidSamlCheck_59";
        }

        // 57: Assertion > Subject > Confirmation > SubjectConfirmationData > Recipient is empty
        String subjectConfirmationDataRecipientValue = subjectConfirmationDataElement.getAttribute("Recipient");
        if (subjectConfirmationDataRecipientValue.isEmpty()) {
            return "SpidSamlCheck_nr57";
        }

        // 61: Assertion > Subject > Confirmation > SubjectConfirmationData > InResponseTo missing
        if (!subjectConfirmationDataElement.hasAttribute("InResponseTo")) {
            return "SpidSamlCheck_nr61";
        }
        
        // 60: Assertion > Subject > Confirmation > SubjectConfirmationData > InResponseTo is empty
        String subjectConfirmationDataInResponseToValue = subjectConfirmationDataElement.getAttribute("InResponseTo");
        if (subjectConfirmationDataInResponseToValue.isEmpty()) {
            return "SpidSamlCheck_nr60";
        }

        // 62: Assertion > Subject > Confirmation > SubjectConfirmationData > InResponseTo does not match request ID
        if (!subjectConfirmationDataInResponseToValue.equals(expectedRequestId)) {
            return "SpidSamlCheck_nr62";
        }

        // 64:  Assertion > Subject > Confirmation > SubjectConfirmationData > NotOnOrAfter missing
        String notOnOrAfter = subjectConfirmationDataElement.getAttribute("NotOnOrAfter");
        if(StringUtil.isNullOrEmpty(notOnOrAfter.trim())){
            return "SpidSamlCheck_64";
        }

        try {
            // 66:  Assertion > Subject > Confirmation > SubjectConfirmationData > NotOnOrAfter before response reception
            XMLGregorianCalendar notOnOrAfterXMLGregorian = DatatypeFactory.newInstance().
                    newXMLGregorianCalendar(notOnOrAfter);
            XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar());

            if(notOnOrAfterXMLGregorian.compare(now) == DatatypeConstants.LESSER){
                return "SpidSamlCheck_66";
            }

        } catch (DatatypeConfigurationException e) {
            logger.error("Could not convert request NotOnOrAfter to XMLGregorianCalendar, wrong format?");
            return "SpidFault_ErrorCode_nr3";
        }
        // 67:  Assertion > Issuer non specified
        Element issuerElement = getDocumentElement(assertionElement, "Issuer");
        if(issuerElement!=null &&
                (issuerElement.getFirstChild()==null ||
                StringUtil.isNullOrEmpty(issuerElement.getFirstChild().getNodeValue()))){
            return "SpidSamlCheck_67";

        }
        // 68:  Assertion > Issuer missing
        if(issuerElement==null){
            return "SpidSamlCheck_68";

        }

        //69 Assertion > Issuer != entityID idp
        if(!issuerElement.getFirstChild().getNodeValue().equals(config.getIdpEntityId())){
            return "SpidSamlCheck_69";
        }
        //70 71 Assertion > Issuer > Format not specified or null
        String format = issuerElement.getAttribute("Format");
        if(StringUtil.isNullOrEmpty(format)){
            return "SpidSamlCheck_7071";
        }

        //72 Assertion > Issuer > Format different than constant
        if(!format.equals(ASSERTION_ISSUER_FORMAT)){
            return "SpidSamlCheck_72";
        }

        //73 Assertion > Conditions missing
        Element conditionsElement = getDocumentElement(assertionElement, "Conditions");
        if(conditionsElement != null && !hasNamedChild(conditionsElement)){
            return "SpidSamlCheck_73";
        }
        //74 Assertion > Conditions is null
        if(conditionsElement==null){
            return "SpidSamlCheck_74";
        }
        //75-76 Assertion > Conditions > NotBefore null or empty
        String notBefore = conditionsElement.getAttribute("NotBefore");
        if(StringUtil.isNullOrEmpty(notBefore)){
            return "SpidSamlCheck_7576";
        }

        //78 Assertion > Condition > NotBefore after response
        try {
            XMLGregorianCalendar notBeforeXmlGregorian = DatatypeFactory.newInstance().
                    newXMLGregorianCalendar(notBefore);
            XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar());

            if(notBeforeXmlGregorian.compare(now) == DatatypeConstants.GREATER){
                return "SpidSamlCheck_78";
            }

        } catch (DatatypeConfigurationException e) {
            logger.error("Could not convert request NotOnOrAfter to XMLGregorianCalendar, wrong format?");
            return "SpidFault_ErrorCode_nr3";
        }

        //79-80 Assertion > Condition > NotOnOrAfter missing or not specified
        String conditionsNotOnOrAfter = conditionsElement.getAttribute("NotOnOrAfter");
        if(StringUtil.isNullOrEmpty(conditionsNotOnOrAfter.trim())){
            return "SpidSamlCheck_7980";
        }

        //82 Assertion > Condition > NotOnOrAfter before response
        try {
            XMLGregorianCalendar conditionsNotOnOrAfterXmlGregorian = DatatypeFactory.newInstance().
                    newXMLGregorianCalendar(conditionsNotOnOrAfter);
            XMLGregorianCalendar now = DatatypeFactory.newInstance().newXMLGregorianCalendar(new GregorianCalendar());

            if(conditionsNotOnOrAfterXmlGregorian.compare(now) == DatatypeConstants.LESSER){
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
        if(!hasNamedChild(audienceRestrictionElement)){
            return "SpidSamlCheck_83";
        }

        //85  86 Assertion > Condition > AudienceRestriction > Audience not specified or missing (note: testing tool 86 xml same as #83)
        if(audience == null || audience.getFirstChild() == null || StringUtil.isNullOrEmpty(audience.getFirstChild().getNodeValue()) ){
            return "SpidSamlCheck_8586";
        }



        //84 Assertion > Condition > AudienceRestriction null (testing tool yaml snippet same as #73)
        if(audienceRestrictionElement==null){
            return "SpidSamlCheck_84";
        }

        //87 Assertion > Condition > AudienceRestriction > Audience != EntityID SP
        String spEntityId = config.getEntityId();
        if(audience.getFirstChild()!= null &&
                !StringUtil.isNullOrEmpty(audience.getFirstChild().getNodeValue()) &&
                !audience.getFirstChild().getNodeValue().equals(spEntityId)){

            return  "SpidSamlCheck_87";

        }

        //88 Assertion > AuthnStatement not specified
        Element authnStatement = getDocumentElement(assertionElement, "AuthnStatement");
        if(authnStatement!= null && !hasNamedChild(authnStatement)){
            return  "SpidSamlCheck_88";
        }
        //89 Assertion > AuthnStatement null
        if(authnStatement==null){
            return  "SpidSamlCheck_89";

        }
        //90 Assertion > AuthnStatement > AuthnContext not specified
        Element authnContextElement = getDocumentElement(authnStatement, "AuthnContext");
        if(authnContextElement!= null && !hasNamedChild(authnContextElement)){
            return  "SpidSamlCheck_90";
        }
        //91 Assertion > AuthnContext > AuthnStatement null note: from IDP same xml response block as #88
        if(authnContextElement==null){
            return  "SpidSamlCheck_91";

        }

        //92 Assertion > AuthnStatement > AuthnContextClassRef unspecified
        Element authnContextClassRef = getDocumentElement(authnContextElement, "AuthnContextClassRef");
        if(authnContextClassRef!= null &&
                (authnContextClassRef.getFirstChild() == null ||
           StringUtil.isNullOrEmpty(authnContextClassRef.getFirstChild().getNodeValue()))){
            return  "SpidSamlCheck_92";

        }

        //93 Assertion > AuthnStatement > AuthnContextClassRef missing note: response snippet same as #90
        if(authnContextClassRef==null){
            return  "SpidSamlCheck_93";
        }
        /**
         *nota: se vi sono più spidLevel specificati in keycloak, la response avrà sempre e solo il primo
         * Non essendo specificato nel tool il preciso comportamento in casi di vari livelli configurati ma solo uno
         * inviato dalla request, si sceglie di controllare che il livello della response sia contenuto tra i livelli
         * configurati su kc (quindi nella config della request)
         */
        //94 Assertion > AuthContextClassRef spid level different from request. This block also implies #95 #96 #97
        String responseSpidLevel = authnContextClassRef.getFirstChild().getNodeValue();
        List<String> requestSpidLevels =Arrays.asList(config.getAuthnContextClassRefs().replaceAll("[\"\\[\\](){}]","").trim().split(","));
        if(!requestSpidLevels.contains(responseSpidLevel)){
            return  "SpidSamlCheck_94";
        }

        //98,99,100,103,104,105,106,107,108 caught by kc
        //109 ok






        return null;
    }

    private Element getDocumentElement(Element assertionElement, String subject) {
        return DocumentUtil.getChildElement(assertionElement,
                new QName(JBossSAMLURIConstants.ASSERTION_NSURI.get(), subject));
    }

    private boolean hasNamedChild(Element element)
    {
        NodeList childNodes = element.getChildNodes();
        if (childNodes == null) return false;

        for (int i = 0; i < childNodes.getLength(); ++i)
        {
            Node node = childNodes.item(i);
            if (node.getNodeType() ==  Node.ELEMENT_NODE && node.getNodeName() != null)
                return true;
        }

        return false;
    }

}
