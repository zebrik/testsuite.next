/*
 * Copyright 2015-2016 Red Hat, Inc, and individual contributors.
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
package org.jboss.hal.testsuite.test.configuration.elytron.othersettings;

import org.jboss.arquillian.core.api.annotation.Inject;
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.dmr.ModelNode;
import org.jboss.hal.resources.Ids;
import org.jboss.hal.testsuite.Console;
import org.jboss.hal.testsuite.CrudOperations;
import org.jboss.hal.testsuite.Random;
import org.jboss.hal.testsuite.creaper.ManagementClientProvider;
import org.jboss.hal.testsuite.fragment.FormFragment;
import org.jboss.hal.testsuite.fragment.TableFragment;
import org.jboss.hal.testsuite.page.configuration.ElytronOtherSettingsPage;
import org.jboss.hal.testsuite.test.configuration.elytron.ElytronFixtures;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.extras.creaper.core.online.ModelNodeResult;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.operations.Operations;
import org.wildfly.extras.creaper.core.online.operations.Values;

import static org.jboss.arquillian.graphene.Graphene.waitGui;
import static org.jboss.hal.dmr.ModelDescriptionConstants.ATTRIBUTES;
import static org.jboss.hal.dmr.ModelDescriptionConstants.CLEAR_TEXT;
import static org.jboss.hal.dmr.ModelDescriptionConstants.CREATE;
import static org.jboss.hal.dmr.ModelDescriptionConstants.CREDENTIAL_REFERENCE;
import static org.jboss.hal.dmr.ModelDescriptionConstants.DEFAULT_REALM;
import static org.jboss.hal.dmr.ModelDescriptionConstants.DIR_CONTEXT;
import static org.jboss.hal.dmr.ModelDescriptionConstants.KEY_MANAGER;
import static org.jboss.hal.dmr.ModelDescriptionConstants.KEY_STORE;
import static org.jboss.hal.dmr.ModelDescriptionConstants.LOCATION;
import static org.jboss.hal.dmr.ModelDescriptionConstants.NAME;
import static org.jboss.hal.dmr.ModelDescriptionConstants.NEW_ITEM_ATTRIBUTES;
import static org.jboss.hal.dmr.ModelDescriptionConstants.NEW_ITEM_PATH;
import static org.jboss.hal.dmr.ModelDescriptionConstants.NEW_ITEM_RDN;
import static org.jboss.hal.dmr.ModelDescriptionConstants.NEW_ITEM_TEMPLATE;
import static org.jboss.hal.dmr.ModelDescriptionConstants.PATH;
import static org.jboss.hal.dmr.ModelDescriptionConstants.PORT;
import static org.jboss.hal.dmr.ModelDescriptionConstants.PROVIDER_NAME;
import static org.jboss.hal.dmr.ModelDescriptionConstants.REALM;
import static org.jboss.hal.dmr.ModelDescriptionConstants.REALMS;
import static org.jboss.hal.dmr.ModelDescriptionConstants.RESULT;
import static org.jboss.hal.dmr.ModelDescriptionConstants.SEARCH_PATH;
import static org.jboss.hal.dmr.ModelDescriptionConstants.TYPE;
import static org.jboss.hal.dmr.ModelDescriptionConstants.URL;
import static org.jboss.hal.dmr.ModelDescriptionConstants.VALUE;
import static org.jboss.hal.resources.Ids.ELYTRON_KEY_MANAGER;
import static org.jboss.hal.resources.Ids.ELYTRON_TRUST_MANAGER;
import static org.jboss.hal.resources.Ids.TAB;
import static org.jboss.hal.testsuite.test.configuration.elytron.ElytronFixtures.*;

@RunWith(Arquillian.class)
public class SslSettingsTest {

    private static final OnlineManagementClient client = ManagementClientProvider.createOnlineManagementClient();
    private static final Operations operations = new Operations(client);
    private static final String PROPERTY_DELIMITER = ".";

    @BeforeClass
    public static void beforeTests() throws Exception {

        // used in key-store, as trust-manager requires a key-store with providers attribute set
        operations.add(providerLoaderAddress(PROV_LOAD_UPDATE));
        operations.add(providerLoaderAddress(PROV_LOAD_UPDATE2));
        operations.add(providerLoaderAddress(PROV_LOAD_UPDATE3));
        operations.add(providerLoaderAddress(PROV_LOAD_DELETE));

        // Stores
        ModelNode credRef = new ModelNode();
        credRef.get(CLEAR_TEXT).set(ANY_STRING);
        Values credParams = Values.of(CREATE, true).and(CREDENTIAL_REFERENCE, credRef).and(LOCATION, ANY_STRING);
        operations.add(credentialStoreAddress(CRED_ST_UPDATE), credParams);
        operations.add(credentialStoreAddress(CRED_ST_DELETE), credParams);

        Values ksParams = Values.of(TYPE, JKS).and(CREDENTIAL_REFERENCE, credRef);
        operations.add(keyStoreAddress(KEY_ST_UPDATE), ksParams);
        operations.add(keyStoreAddress(KEY_ST_CR_UPDATE), ksParams);
        operations.add(keyStoreAddress(KEY_ST_DELETE), ksParams);
        operations.writeAttribute(keyStoreAddress(KEY_ST_UPDATE), PROVIDERS, PROV_LOAD_UPDATE);

        operations.add(filteringKeyStoreAddress(FILT_ST_DELETE),
                Values.of(ALIAS_FILTER, ANY_STRING).and(KEY_STORE, KEY_ST_UPDATE));
        operations.add(filteringKeyStoreAddress(FILT_ST_UPDATE),
                Values.of(ALIAS_FILTER, ANY_STRING).and(KEY_STORE, KEY_ST_UPDATE));

        operations.add(dirContextAddress(DIR_UPDATE), Values.of(URL, ANY_STRING));
        operations.add(dirContextAddress(DIR_DELETE), Values.of(URL, ANY_STRING));

        Values dirCtxParams = Values.of(URL, ANY_STRING)
                .andObject(CREDENTIAL_REFERENCE, Values.of(CLEAR_TEXT, ANY_STRING));
        operations.add(dirContextAddress(DIR_CR_CRT), Values.of(URL, ANY_STRING));
        operations.add(dirContextAddress(DIR_CR_UPD), dirCtxParams);
        operations.add(dirContextAddress(DIR_CR_DEL), dirCtxParams);

        Values ldapKsValues = Values.of(DIR_CONTEXT, DIR_UPDATE).and(SEARCH_PATH, ANY_STRING);
        ModelNode props = new ModelNode();
        props.get(NAME).set("p1");
        props.get(VALUE).add(Random.name());
        ModelNode newItemTemplate = new ModelNode();
        newItemTemplate.get(NEW_ITEM_PATH).set(ANY_STRING);
        newItemTemplate.get(NEW_ITEM_RDN).set(ANY_STRING);
        newItemTemplate.get(NEW_ITEM_ATTRIBUTES).add(props);

        operations.add(ldapKeyStoreAddress(LDAPKEY_ST_UPDATE), ldapKsValues);
        operations.add(ldapKeyStoreAddress(LDAPKEY_ST_DELETE), ldapKsValues);
        operations.add(ldapKeyStoreAddress(LDAPKEY_ST_TEMP1_UPDATE), ldapKsValues);
        operations.add(ldapKeyStoreAddress(LDAPKEY_ST_TEMP2_DELETE), ldapKsValues);
        operations.add(ldapKeyStoreAddress(LDAPKEY_ST_TEMP3_ADD), ldapKsValues);
        operations.add(ldapKeyStoreAddress(LDAPKEY_ST_TEMP4_TRY_ADD), ldapKsValues);
        operations.writeAttribute(ldapKeyStoreAddress(LDAPKEY_ST_TEMP1_UPDATE), NEW_ITEM_TEMPLATE, newItemTemplate);
        operations.writeAttribute(ldapKeyStoreAddress(LDAPKEY_ST_TEMP2_DELETE), NEW_ITEM_TEMPLATE, newItemTemplate);

        // SSL
        Values aggValues = Values.ofList(PROVIDERS, PROV_LOAD_UPDATE, PROV_LOAD_UPDATE2);
        operations.add(aggregateProvidersAddress(AGG_PRV_DELETE), aggValues);
        operations.add(aggregateProvidersAddress(AGG_PRV_UPDATE), aggValues);

        operations.add(clientSslContextAddress(CLI_SSL_DELETE));
        operations.add(clientSslContextAddress(CLI_SSL_UPDATE));

        Values keyManagerValues = Values.of(KEY_STORE, KEY_ST_UPDATE)
                .andObject(CREDENTIAL_REFERENCE, Values.of(CLEAR_TEXT, ANY_STRING));
        operations.add(keyManagerAddress(KEY_MAN_UPDATE), keyManagerValues);
        operations.add(keyManagerAddress(KEY_MAN_TRY_UPDATE), keyManagerValues);
        operations.add(keyManagerAddress(KEY_MAN_DELETE), keyManagerValues);

        Values serverSslContextValues = Values.of(KEY_MANAGER, KEY_MAN_UPDATE);
        operations.add(serverSslContextAddress(SRV_SSL_DELETE), serverSslContextValues);
        operations.add(serverSslContextAddress(SRV_SSL_UPDATE), serverSslContextValues);

        // a realm is required for new security-domain
        operations.add(filesystemRealmAddress(FILESYS_RLM_CREATE), Values.of(PATH, ANY_STRING));
        operations.add(filesystemRealmAddress(FILESYS_RLM_UPDATE), Values.of(PATH, ANY_STRING));
        ModelNode realmNode1 = new ModelNode();
        realmNode1.get(REALM).set(FILESYS_RLM_UPDATE);
        ModelNode realmNode2 = new ModelNode();
        realmNode2.get(REALM).set(FILESYS_RLM_CREATE);
        Values secDomainParams = Values.of(DEFAULT_REALM, FILESYS_RLM_UPDATE).andList(REALMS, realmNode1);
        operations.add(securityDomainAddress(SEC_DOM_UPDATE), secDomainParams);
        operations.add(securityDomainAddress(SEC_DOM_UPDATE2), secDomainParams);
        operations.add(securityDomainAddress(SEC_DOM_UPDATE3),
                Values.of(DEFAULT_REALM, FILESYS_RLM_UPDATE).andList(REALMS, realmNode1, realmNode2));
        operations.add(securityDomainAddress(SEC_DOM_DELETE));

        operations.add(trustManagerAddress(TRU_MAN_UPDATE), Values.of(KEY_STORE, KEY_ST_UPDATE));
        operations.add(trustManagerAddress(TRU_MAN_DELETE), Values.of(KEY_STORE, KEY_ST_UPDATE));

        Values trustParams = Values.of(KEY_STORE, KEY_ST_UPDATE).andObject(CERTIFICATE_REVOCATION_LIST,
                        Values.of(PATH, "${jboss.server.config.dir}/logging.properties"));
        operations.add(trustManagerAddress(TRU_MAN_CRL_CRT), Values.of(KEY_STORE, KEY_ST_UPDATE));
        operations.add(trustManagerAddress(TRU_MAN_CRL_UPD), trustParams);
        operations.add(trustManagerAddress(TRU_MAN_CRL_DEL), trustParams);

        operations.add(constantPrincipalTransformerAddress(CONS_PRI_TRANS_UPDATE), Values.of(CONSTANT, ANY_STRING));

        operations.add(authenticationConfigurationAddress(AUT_CF_UPDATE));
        operations.add(authenticationConfigurationAddress(AUT_CF_DELETE));

        Values autParams = Values.ofObject(CREDENTIAL_REFERENCE, Values.of(CLEAR_TEXT, ANY_STRING));
        operations.add(authenticationConfigurationAddress(AUT_CF_CR_CRT));
        operations.add(authenticationConfigurationAddress(AUT_CF_CR_UPD), autParams);
        operations.add(authenticationConfigurationAddress(AUT_CF_CR_DEL), autParams);

        operations.add(authenticationContextAddress(AUT_CT_DELETE));
        operations.add(authenticationContextAddress(AUT_CT_UPDATE));
        ModelNode matchRuleUpdate = new ModelNode();
        matchRuleUpdate.get(MATCH_ABSTRACT_TYPE).set(AUT_CT_MR_UPDATE);
        ModelNode matchRuleDelete = new ModelNode();
        matchRuleDelete.get(MATCH_ABSTRACT_TYPE).set(AUT_CT_MR_DELETE);
        operations.add(authenticationContextAddress(AUT_CT_UPDATE2),
                Values.ofList(MATCH_RULES, matchRuleUpdate, matchRuleDelete));

        operations.add(fileAuditLogAddress(FILE_LOG_DELETE), Values.of(PATH, ANY_STRING));
        operations.add(fileAuditLogAddress(FILE_LOG_UPDATE), Values.of(PATH, ANY_STRING));
        operations.add(fileAuditLogAddress(FILE_LOG_TRY_UPDATE), Values.of(PATH, ANY_STRING));

        Values params = Values.of(PATH, ANY_STRING).and(SUFFIX, SUFFIX_LOG);
        operations.add(periodicRotatingFileAuditLogAddress(PER_LOG_DELETE), params);
        operations.add(periodicRotatingFileAuditLogAddress(PER_LOG_UPDATE), params);
        operations.add(periodicRotatingFileAuditLogAddress(PER_LOG_TRY_UPDATE), params);

        operations.add(sizeRotatingFileAuditLogAddress(SIZ_LOG_DELETE), Values.of(PATH, ANY_STRING));
        operations.add(sizeRotatingFileAuditLogAddress(SIZ_LOG_UPDATE), Values.of(PATH, ANY_STRING));

        Values syslogParams = Values.of(HOSTNAME, ANY_STRING).and(PORT, Random.number()).and(SERVER_ADDRESS, LOCALHOST);
        operations.add(syslogAuditLogAddress(SYS_LOG_UPDATE), syslogParams);
        operations.add(syslogAuditLogAddress(SYS_LOG_TRY_UPDATE), syslogParams);
        operations.add(syslogAuditLogAddress(SYS_LOG_DELETE), syslogParams);

        Values secEventParams = Values.ofList(SECURITY_EVENT_LISTENERS, SYS_LOG_UPDATE, SIZ_LOG_UPDATE);
        operations.add(aggregateSecurityEventListenerAddress(AGG_SEC_UPDATE), secEventParams);
        operations.add(aggregateSecurityEventListenerAddress(AGG_SEC_DELETE), secEventParams);
    }

    @AfterClass
    public static void tearDown() throws Exception {
        // Stores
        operations.remove(credentialStoreAddress(CRED_ST_DELETE));
        operations.remove(credentialStoreAddress(CRED_ST_UPDATE));
        operations.remove(credentialStoreAddress(CRED_ST_CREATE));

        operations.remove(filteringKeyStoreAddress(FILT_ST_DELETE));
        operations.remove(filteringKeyStoreAddress(FILT_ST_UPDATE));
        operations.remove(filteringKeyStoreAddress(FILT_ST_CREATE));

        operations.remove(keyStoreAddress(KEY_ST_CREATE));
        operations.remove(keyStoreAddress(KEY_ST_DELETE));

        operations.remove(ldapKeyStoreAddress(LDAPKEY_ST_DELETE));
        operations.remove(ldapKeyStoreAddress(LDAPKEY_ST_UPDATE));
        operations.remove(ldapKeyStoreAddress(LDAPKEY_ST_TEMP1_UPDATE));
        operations.remove(ldapKeyStoreAddress(LDAPKEY_ST_TEMP2_DELETE));
        operations.remove(ldapKeyStoreAddress(LDAPKEY_ST_TEMP3_ADD));
        operations.remove(ldapKeyStoreAddress(LDAPKEY_ST_TEMP4_TRY_ADD));
        operations.remove(ldapKeyStoreAddress(LDAPKEY_ST_CREATE));

        operations.remove(dirContextAddress(DIR_UPDATE));
        operations.remove(dirContextAddress(DIR_DELETE));
        operations.remove(dirContextAddress(DIR_CREATE));
        operations.remove(dirContextAddress(DIR_CR_CRT));
        operations.remove(dirContextAddress(DIR_CR_UPD));
        operations.remove(dirContextAddress(DIR_CR_DEL));

        // SSL
        operations.remove(aggregateProvidersAddress(AGG_PRV_DELETE));
        operations.remove(aggregateProvidersAddress(AGG_PRV_UPDATE));
        operations.remove(aggregateProvidersAddress(AGG_PRV_CREATE));

        operations.remove(clientSslContextAddress(CLI_SSL_UPDATE));
        operations.remove(clientSslContextAddress(CLI_SSL_CREATE));
        operations.remove(clientSslContextAddress(CLI_SSL_DELETE));

        // remove the server-ssl-context before removing key-manager
        operations.remove(serverSslContextAddress(SRV_SSL_UPDATE));
        operations.remove(serverSslContextAddress(SRV_SSL_CREATE));
        operations.remove(serverSslContextAddress(SRV_SSL_DELETE));

        operations.remove(keyManagerAddress(KEY_MAN_CREATE));
        operations.remove(keyManagerAddress(KEY_MAN_UPDATE));
        operations.remove(keyManagerAddress(KEY_MAN_TRY_UPDATE));
        operations.remove(keyManagerAddress(KEY_MAN_DELETE));

        operations.remove(securityDomainAddress(SEC_DOM_UPDATE));
        operations.remove(securityDomainAddress(SEC_DOM_UPDATE2));
        operations.remove(securityDomainAddress(SEC_DOM_UPDATE3));
        operations.remove(securityDomainAddress(SEC_DOM_DELETE));
        operations.remove(securityDomainAddress(SEC_DOM_CREATE));

        operations.remove(trustManagerAddress(TRU_MAN_UPDATE));
        operations.remove(trustManagerAddress(TRU_MAN_CREATE));
        operations.remove(trustManagerAddress(TRU_MAN_DELETE));
        operations.remove(trustManagerAddress(TRU_MAN_CRL_CRT));
        operations.remove(trustManagerAddress(TRU_MAN_CRL_UPD));
        operations.remove(trustManagerAddress(TRU_MAN_CRL_DEL));

        // key-store is a dependency on key-manager and trust-manager, remove it after key-manager and trust-manager
        operations.remove(keyStoreAddress(KEY_ST_UPDATE));
        operations.remove(keyStoreAddress(KEY_ST_CR_UPDATE));

        operations.remove(providerLoaderAddress(PROV_LOAD_UPDATE));
        operations.remove(providerLoaderAddress(PROV_LOAD_UPDATE2));
        operations.remove(providerLoaderAddress(PROV_LOAD_UPDATE3));
        operations.remove(providerLoaderAddress(PROV_LOAD_CREATE));
        operations.remove(providerLoaderAddress(PROV_LOAD_DELETE));

        operations.remove(filesystemRealmAddress(FILESYS_RLM_UPDATE));
        operations.remove(filesystemRealmAddress(FILESYS_RLM_CREATE));

        operations.remove(constantPrincipalTransformerAddress(CONS_PRI_TRANS_UPDATE));

        operations.remove(authenticationContextAddress(AUT_CT_UPDATE));
        operations.remove(authenticationContextAddress(AUT_CT_UPDATE2));
        operations.remove(authenticationContextAddress(AUT_CT_DELETE));
        operations.remove(authenticationContextAddress(AUT_CT_CREATE));

        operations.remove(authenticationConfigurationAddress(AUT_CF_CREATE));
        operations.remove(authenticationConfigurationAddress(AUT_CF_UPDATE));
        operations.remove(authenticationConfigurationAddress(AUT_CF_DELETE));
        operations.remove(authenticationConfigurationAddress(AUT_CF_CR_CRT));
        operations.remove(authenticationConfigurationAddress(AUT_CF_CR_UPD));
        operations.remove(authenticationConfigurationAddress(AUT_CF_CR_DEL));

        operations.remove(fileAuditLogAddress(FILE_LOG_DELETE));
        operations.remove(fileAuditLogAddress(FILE_LOG_UPDATE));
        operations.remove(fileAuditLogAddress(FILE_LOG_TRY_UPDATE));
        operations.remove(fileAuditLogAddress(FILE_LOG_CREATE));

        // remove the aggregate-security-event-listener first, as they require size audit log and syslog
        operations.remove(aggregateSecurityEventListenerAddress(AGG_SEC_UPDATE));
        operations.remove(aggregateSecurityEventListenerAddress(AGG_SEC_CREATE));
        operations.remove(aggregateSecurityEventListenerAddress(AGG_SEC_DELETE));

        operations.remove(periodicRotatingFileAuditLogAddress(PER_LOG_UPDATE));
        operations.remove(periodicRotatingFileAuditLogAddress(PER_LOG_TRY_UPDATE));
        operations.remove(periodicRotatingFileAuditLogAddress(PER_LOG_DELETE));
        operations.remove(periodicRotatingFileAuditLogAddress(PER_LOG_CREATE));

        operations.remove(sizeRotatingFileAuditLogAddress(SIZ_LOG_DELETE));
        operations.remove(sizeRotatingFileAuditLogAddress(SIZ_LOG_UPDATE));
        operations.remove(sizeRotatingFileAuditLogAddress(SIZ_LOG_CREATE));

        operations.remove(syslogAuditLogAddress(SYS_LOG_DELETE));
        operations.remove(syslogAuditLogAddress(SYS_LOG_CREATE));
        operations.remove(syslogAuditLogAddress(SYS_LOG_UPDATE));
        operations.remove(syslogAuditLogAddress(SYS_LOG_TRY_UPDATE));

        operations.remove(policyAddress(POL_CREATE));

    }

    @Page private ElytronOtherSettingsPage page;
    @Inject private Console console;
    @Inject private CrudOperations crud;

    @Before
    public void setUp() throws Exception {
        page.navigate();
    }

    // --------------- aggregate-providers

    @Test
    public void aggregateProvidersCreate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, AGGREGATE_PROVIDERS_ITEM);
        TableFragment table = page.getAggregateProvidersTable();

        crud.create(aggregateProvidersAddress(AGG_PRV_CREATE), table, f -> {
            f.text(NAME, AGG_PRV_CREATE);
            f.list(PROVIDERS).add(PROV_LOAD_UPDATE).add(PROV_LOAD_UPDATE2);
        });
    }

    @Test
    public void aggregateProvidersTryCreate() {
        console.verticalNavigation().selectSecondary(SSL_ITEM, AGGREGATE_PROVIDERS_ITEM);
        TableFragment table = page.getAggregateProvidersTable();

        crud.createWithErrorAndCancelDialog(table, AGG_PRV_CREATE, PROVIDERS);
    }

    @Test
    public void aggregateProvidersUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, AGGREGATE_PROVIDERS_ITEM);
        TableFragment table = page.getAggregateProvidersTable();
        FormFragment form = page.getAggregateProvidersForm();
        table.bind(form);
        table.select(AGG_PRV_UPDATE);

        crud.update(aggregateProvidersAddress(AGG_PRV_UPDATE), form, f -> f.list(PROVIDERS).add(PROV_LOAD_UPDATE3), verify -> verify.verifyListAttributeContainsValue(PROVIDERS, PROV_LOAD_UPDATE3));
    }

    @Test
    public void aggregateProvidersDelete() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, AGGREGATE_PROVIDERS_ITEM);
        TableFragment table = page.getAggregateProvidersTable();

        crud.delete(aggregateProvidersAddress(AGG_PRV_DELETE), table, AGG_PRV_DELETE);
    }

    // --------------- client-ssl-context

    @Test
    public void clientSslContextCreate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, CLIENT_SSL_CONTEXT_ITEM);
        TableFragment table = page.getClientSslContextTable();

        crud.create(clientSslContextAddress(CLI_SSL_CREATE), table, CLI_SSL_CREATE);
    }

    @Test
    public void clientSslContextUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, CLIENT_SSL_CONTEXT_ITEM);
        TableFragment table = page.getClientSslContextTable();
        FormFragment form = page.getClientSslContextForm();
        table.bind(form);
        table.select(CLI_SSL_UPDATE);

        crud.update(clientSslContextAddress(CLI_SSL_UPDATE), form, PROVIDER_NAME);
    }

    @Test
    public void clientSslContextDelete() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, CLIENT_SSL_CONTEXT_ITEM);
        TableFragment table = page.getClientSslContextTable();

        crud.delete(clientSslContextAddress(CLI_SSL_DELETE), table, CLI_SSL_DELETE);
    }

    // --------------- key-manager

    @Test
    public void keyManagerCreate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, KEY_MANAGER_ITEM);
        TableFragment table = page.getKeyManagerTable();

        crud.create(keyManagerAddress(KEY_MAN_CREATE), table, f -> {
            f.text(NAME, KEY_MAN_CREATE);
            f.text(KEY_STORE, KEY_ST_UPDATE);
            f.text(CLEAR_TEXT, ANY_STRING);
        });
    }

    @Test
    public void keyManagerTryCreate() {
        console.verticalNavigation().selectSecondary(SSL_ITEM, KEY_MANAGER_ITEM);
        TableFragment table = page.getKeyManagerTable();

        crud.createWithErrorAndCancelDialog(table, KEY_MAN_CREATE, KEY_STORE);
    }

    @Test
    public void keyManagerUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, KEY_MANAGER_ITEM);
        TableFragment table = page.getKeyManagerTable();
        FormFragment form = page.getKeyManagerForm();
        table.bind(form);
        table.select(KEY_MAN_UPDATE);
        page.getKeyManagerTab().select(Ids.build(ELYTRON_KEY_MANAGER, ATTRIBUTES, TAB));

        crud.update(keyManagerAddress(KEY_MAN_UPDATE), form, PROVIDER_NAME);
    }

    @Test
    public void keyManagerTryUpdate() {
        console.verticalNavigation().selectSecondary(SSL_ITEM, KEY_MANAGER_ITEM);
        TableFragment table = page.getKeyManagerTable();
        FormFragment form = page.getKeyManagerForm();
        table.bind(form);
        table.select(KEY_MAN_TRY_UPDATE);
        page.getKeyManagerTab().select(Ids.build(ELYTRON_KEY_MANAGER, ATTRIBUTES, TAB));

        crud.updateWithError(form, f -> f.clear(KEY_STORE), KEY_STORE);
    }

    @Test
    public void keyManagerDelete() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, KEY_MANAGER_ITEM);
        TableFragment table = page.getKeyManagerTable();

        crud.delete(keyManagerAddress(KEY_MAN_DELETE), table, KEY_MAN_DELETE);
    }

    @Test
    public void keyManagerCredentialReferenceUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, KEY_MANAGER_ITEM);
        TableFragment table = page.getKeyManagerTable();
        FormFragment form = page.getKeyManagerCredentialReferenceForm();
        table.bind(form);
        table.select(KEY_MAN_UPDATE);
        page.getKeyManagerTab().select(Ids.build(ELYTRON_KEY_MANAGER, CREDENTIAL_REFERENCE, TAB));
        crud.update(keyManagerAddress(KEY_MAN_UPDATE), form, f -> f.text(CLEAR_TEXT, ANY_STRING),
                ver -> ver.verifyAttribute(CREDENTIAL_REFERENCE + PROPERTY_DELIMITER + CLEAR_TEXT, ANY_STRING));
    }

    // --------------- provider-loader

    @Test
    public void providerLoaderCreate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, PROVIDER_LOADER_ITEM);
        TableFragment table = page.getProviderLoaderTable();

        crud.create(providerLoaderAddress(PROV_LOAD_CREATE), table, PROV_LOAD_CREATE);
    }

    @Test
    public void providerLoaderUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, PROVIDER_LOADER_ITEM);
        TableFragment table = page.getProviderLoaderTable();
        FormFragment form = page.getProviderLoaderForm();
        table.bind(form);
        table.select(PROV_LOAD_UPDATE);
        crud.update(providerLoaderAddress(PROV_LOAD_UPDATE), form, PATH, ANY_STRING);
    }

    @Test
    public void providerLoaderDelete() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, PROVIDER_LOADER_ITEM);
        TableFragment table = page.getProviderLoaderTable();

        crud.delete(providerLoaderAddress(PROV_LOAD_DELETE), table, PROV_LOAD_DELETE);
    }

    // --------------- provider-loader

    @Test
    public void serverSslContextCreate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, SERVER_SSL_CONTEXT_ITEM);
        TableFragment table = page.getServerSslContextTable();

        crud.create(serverSslContextAddress(SRV_SSL_CREATE), table, f -> {
            f.text(NAME, SRV_SSL_CREATE);
            f.text(KEY_MANAGER, KEY_MAN_UPDATE);
        });
    }

    @Test
    public void serverSslContextTryCreate() {
        console.verticalNavigation().selectSecondary(SSL_ITEM, SERVER_SSL_CONTEXT_ITEM);
        TableFragment table = page.getServerSslContextTable();

        crud.createWithErrorAndCancelDialog(table, SRV_SSL_CREATE, KEY_MANAGER);
    }

    @Test
    public void serverSslContextUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, SERVER_SSL_CONTEXT_ITEM);
        TableFragment table = page.getServerSslContextTable();
        FormFragment form = page.getServerSslContextForm();
        table.bind(form);
        table.select(SRV_SSL_UPDATE);

        crud.update(serverSslContextAddress(SRV_SSL_UPDATE), form, PROVIDER_NAME, ANY_STRING);
    }

    @Test
    public void serverSslContextTryUpdate() {
        console.verticalNavigation().selectSecondary(SSL_ITEM, SERVER_SSL_CONTEXT_ITEM);
        TableFragment table = page.getServerSslContextTable();
        FormFragment form = page.getServerSslContextForm();
        table.bind(form);
        table.select(SRV_SSL_UPDATE);

        crud.updateWithError(form, f -> f.clear(KEY_MANAGER), KEY_MANAGER);
    }

    @Test
    public void serverSslContextDelete() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, SERVER_SSL_CONTEXT_ITEM);
        TableFragment table = page.getServerSslContextTable();

        crud.delete(serverSslContextAddress(SRV_SSL_DELETE), table, SRV_SSL_DELETE);
    }

    // --------------- security-domain

    @Test
    public void securityDomainCreate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, SECURITY_DOMAIN_ITEM);
        TableFragment table = page.getSecurityDomainTable();

        crud.create(securityDomainAddress(SEC_DOM_CREATE), table, f -> {
            f.text(NAME, SEC_DOM_CREATE);
            f.text(DEFAULT_REALM, FILESYS_RLM_UPDATE);
        });
    }

    @Test
    public void securityDomainUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, SECURITY_DOMAIN_ITEM);
        TableFragment table = page.getSecurityDomainTable();
        FormFragment form = page.getSecurityDomainForm();
        table.bind(form);
        table.select(SEC_DOM_UPDATE);
        crud.update(securityDomainAddress(SEC_DOM_UPDATE), form,
                f -> f.list(OUTFLOW_SECURITY_DOMAINS).add(SEC_DOM_UPDATE2),
                verify -> verify.verifyListAttributeContainsValue(OUTFLOW_SECURITY_DOMAINS, SEC_DOM_UPDATE2));
    }

    @Test
    public void securityDomainDelete() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, SECURITY_DOMAIN_ITEM);
        TableFragment table = page.getSecurityDomainTable();
        crud.delete(securityDomainAddress(SEC_DOM_DELETE), table, SEC_DOM_DELETE);
    }

    @Test
    public void securityDomainRealmsCreate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, SECURITY_DOMAIN_ITEM);
        TableFragment secDomaintable = page.getSecurityDomainTable();
        TableFragment table = page.getSecurityDomainRealmsTable();

        secDomaintable.action(SEC_DOM_UPDATE, ElytronFixtures.REALMS);
        waitGui().until().element(table.getRoot()).is().visible();

        try {
            crud.create(securityDomainAddress(SEC_DOM_UPDATE), table, f -> f.text(REALM, FILESYS_RLM_CREATE),
                    vc -> vc.verifyListAttributeContainsSingleValue(REALMS, REALM, FILESYS_RLM_CREATE));
        } finally {
            // getting rid of action selection
            page.getSecurityDomainPages().breadcrumb().getBackToMainPage();
        }
    }

    @Test
    public void securityDomainRealmsTryCreate() {
        console.verticalNavigation().selectSecondary(SSL_ITEM, SECURITY_DOMAIN_ITEM);
        TableFragment secDomaintable = page.getSecurityDomainTable();
        TableFragment table = page.getSecurityDomainRealmsTable();

        secDomaintable.action(SEC_DOM_UPDATE, ElytronFixtures.REALMS);
        waitGui().until().element(table.getRoot()).is().visible();

        try {
            crud.createWithErrorAndCancelDialog(table, f -> f.text("role-decoder", ANY_STRING), REALM);
        } finally {
            // getting rid of action selection
            page.getSecurityDomainPages().breadcrumb().getBackToMainPage();
        }
    }

    @Test
    public void securityDomainRealmsUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, SECURITY_DOMAIN_ITEM);
        TableFragment secDomaintable = page.getSecurityDomainTable();
        TableFragment table = page.getSecurityDomainRealmsTable();
        FormFragment form = page.getSecurityDomainRealmsForm();

        secDomaintable.action(SEC_DOM_UPDATE2, ElytronFixtures.REALMS);
        waitGui().until().element(table.getRoot()).is().visible();
        table.bind(form);
        table.select(FILESYS_RLM_UPDATE);

        try {
            crud.update(securityDomainAddress(SEC_DOM_UPDATE2), form,
                    f -> f.text(PRINCIPAL_TRANSFORMER, CONS_PRI_TRANS_UPDATE),
                    vc -> vc.verifyListAttributeContainsSingleValue(REALMS, PRINCIPAL_TRANSFORMER, CONS_PRI_TRANS_UPDATE));
        } finally {
            // getting rid of action selection
            page.getSecurityDomainPages().breadcrumb().getBackToMainPage();
        }
    }

    @Test
    public void securityDomainRealmsDelete() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, SECURITY_DOMAIN_ITEM);
        TableFragment secDomaintable = page.getSecurityDomainTable();
        TableFragment table = page.getSecurityDomainRealmsTable();

        secDomaintable.action(SEC_DOM_UPDATE3, ElytronFixtures.REALMS);
        waitGui().until().element(table.getRoot()).is().visible();

        try {
            crud.delete(securityDomainAddress(SEC_DOM_UPDATE3), table, FILESYS_RLM_CREATE,
                    vc -> vc.verifyListAttributeDoesNotContainSingleValue(REALMS, REALM, FILESYS_RLM_CREATE));
        } finally {
            // getting rid of action selection
            page.getSecurityDomainPages().breadcrumb().getBackToMainPage();
        }
    }

    // --------------- trust-manager

    @Test
    public void trustManagerCreate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, TRUST_MANAGER_ITEM);
        TableFragment table = page.getTrustManagerTable();

        crud.create(trustManagerAddress(TRU_MAN_CREATE), table, f -> {
            f.text(NAME, TRU_MAN_CREATE);
            f.text(KEY_STORE, KEY_ST_UPDATE);
        });
    }

    @Test
    public void trustManagerTryCreate() {
        console.verticalNavigation().selectSecondary(SSL_ITEM, TRUST_MANAGER_ITEM);
        TableFragment table = page.getTrustManagerTable();
        crud.createWithErrorAndCancelDialog(table, TRU_MAN_CREATE, KEY_STORE);
    }

    @Test
    public void trustManagerUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, TRUST_MANAGER_ITEM);
        TableFragment table = page.getTrustManagerTable();
        FormFragment form = page.getTrustManagerForm();
        table.bind(form);
        table.select(TRU_MAN_UPDATE);
        page.getTrustManagerTab().select(Ids.build(ELYTRON_TRUST_MANAGER, ATTRIBUTES, TAB));
        crud.update(trustManagerAddress(TRU_MAN_UPDATE), form, f -> f.text(PROVIDER_NAME, ANY_STRING),
                verify -> verify.verifyAttribute(PROVIDER_NAME, ANY_STRING));
    }

    @Test
    public void trustManagerCertificateRevocationListAdd() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, TRUST_MANAGER_ITEM);
        TableFragment table = page.getTrustManagerTable();
        FormFragment form = page.getTrustManagerCertificateRevocationListForm();
        table.bind(form);
        table.select(TRU_MAN_CRL_CRT);
        page.getTrustManagerTab().select(Ids.build(ELYTRON_TRUST_MANAGER, CERTIFICATE_REVOCATION_LIST, TAB));
        form.emptyState().mainAction();
        console.verifySuccess();
        // the UI "add" operation adds a certificate-revocation-list with no inner attributes, as they are not required
        ModelNodeResult actualResult = operations.readAttribute(trustManagerAddress(TRU_MAN_CRL_CRT),
                CERTIFICATE_REVOCATION_LIST);
        Assert.assertTrue("attribute certificate-revocation-list should exist", actualResult.get(RESULT).isDefined());
    }

    @Test
    public void trustManagerCertificateRevocationListUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, TRUST_MANAGER_ITEM);
        TableFragment table = page.getTrustManagerTable();
        FormFragment form = page.getTrustManagerCertificateRevocationListForm();
        table.bind(form);
        table.select(TRU_MAN_CRL_UPD);
        page.getTrustManagerTab().select(Ids.build(ELYTRON_TRUST_MANAGER, CERTIFICATE_REVOCATION_LIST, TAB));
        crud.update(trustManagerAddress(TRU_MAN_CRL_UPD), form, f -> f.text(PATH, ANY_STRING),
                verify -> verify.verifyAttribute(CERTIFICATE_REVOCATION_LIST + PROPERTY_DELIMITER + PATH, ANY_STRING));
    }

    @Test
    public void trustManagerCertificateRevocationListDelete() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, TRUST_MANAGER_ITEM);
        TableFragment table = page.getTrustManagerTable();
        FormFragment form = page.getTrustManagerCertificateRevocationListForm();
        table.bind(form);
        table.select(TRU_MAN_CRL_DEL);
        page.getTrustManagerTab().select(Ids.build(ELYTRON_TRUST_MANAGER, CERTIFICATE_REVOCATION_LIST, TAB));
        crud.deleteSingleton(trustManagerAddress(TRU_MAN_CRL_DEL), form,
                verify -> verify.verifyAttributeIsUndefined(CERTIFICATE_REVOCATION_LIST));
    }

    @Test
    public void trustManagerDelete() throws Exception {
        console.verticalNavigation().selectSecondary(SSL_ITEM, TRUST_MANAGER_ITEM);
        TableFragment table = page.getTrustManagerTable();
        crud.delete(trustManagerAddress(TRU_MAN_DELETE), table, TRU_MAN_DELETE);
    }
}
