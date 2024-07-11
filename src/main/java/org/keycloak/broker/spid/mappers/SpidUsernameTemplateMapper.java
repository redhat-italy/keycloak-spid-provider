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

package org.keycloak.broker.spid.mappers;

import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.saml.mappers.UsernameTemplateMapper;
import org.keycloak.broker.spid.SpidIdentityProviderFactory;
import org.keycloak.dom.saml.v2.assertion.*;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SpidUsernameTemplateMapper extends UsernameTemplateMapper  {

    public static final String[] COMPATIBLE_PROVIDERS = {SpidIdentityProviderFactory.PROVIDER_ID};

    public static final String PROVIDER_ID = "spid-saml-username-idp-mapper";

    private static final Pattern SUBSTITUTION = Pattern.compile("\\$\\{([^}]+?)(?:\\s*\\|\\s*(\\S+)\\s*)?\\}");

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayType() {
        return "SPID Username Template Importer";
    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        this.setUserNameFromTemplate(mapperModel, context);
    }

    private void setUserNameFromTemplate(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        AssertionType assertion = (AssertionType)context.getContextData().get("SAML_ASSERTION");
        String template = mapperModel.getConfig().get("template");
        Matcher m = SUBSTITUTION.matcher(template);
        StringBuffer sb = new StringBuffer();

        while(true) {
            while(m.find()) {
                String variable = m.group(1);
                Optional var10000 = Optional.ofNullable(m.group(2));
                Map var10001 = TRANSFORMERS;
                var10001.getClass();
                UnaryOperator<String> transformer = (UnaryOperator)var10000.map(var10001::get).orElse(UnaryOperator.identity());
                if (variable.equals("ALIAS")) {
                    m.appendReplacement(sb, transformer.apply(context.getIdpConfig().getAlias()));
                } else if (variable.equals("UUID")) {
                    m.appendReplacement(sb, transformer.apply(KeycloakModelUtils.generateId()));
                } else if (variable.equals("NAMEID")) {
                    SubjectType subject = assertion.getSubject();
                    SubjectType.STSubType subType = subject.getSubType();
                    NameIDType subjectNameID = (NameIDType)subType.getBaseID();
                    m.appendReplacement(sb, transformer.apply(subjectNameID.getValue()));
                } else if (!variable.startsWith("ATTRIBUTE.")) {
                    m.appendReplacement(sb, m.group(1));
                } else {
                    String name = variable.substring("ATTRIBUTE.".length());
                    String value = "";
                    Iterator var11 = assertion.getAttributeStatements().iterator();

                    while(true) {
                        while(var11.hasNext()) {
                            AttributeStatementType statement = (AttributeStatementType)var11.next();
                            Iterator var13 = statement.getAttributes().iterator();

                            while(var13.hasNext()) {
                                AttributeStatementType.ASTChoiceType choice = (AttributeStatementType.ASTChoiceType)var13.next();
                                AttributeType attr = choice.getAttribute();
                                if (name.equals(attr.getName()) || name.equals(attr.getFriendlyName())) {
                                    List<Object> attributeValue = attr.getAttributeValue();
                                    if (attributeValue != null && !attributeValue.isEmpty()) {
                                        value = attributeValue.get(0).toString();
                                    }
                                    break;
                                }
                            }
                        }

                        //strip TINIT- from fiscalNumber
                        if(value.toUpperCase().startsWith("TINIT-"))
                            value = value.split("^(?i)TINIT-")[1];


                        m.appendReplacement(sb,transformer.apply(value));
                        break;
                    }
                }
            }

            m.appendTail(sb);
            UsernameTemplateMapper.Target t = getTarget((String)mapperModel.getConfig().get("target"));
            t.set(context, sb.toString());
            return;
        }
    }





}
