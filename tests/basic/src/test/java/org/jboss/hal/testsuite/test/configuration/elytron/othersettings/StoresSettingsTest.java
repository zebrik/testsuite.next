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
import org.jboss.hal.testsuite.fragment.AddResourceDialogFragment;
import org.jboss.hal.testsuite.fragment.EmptyState;
import org.jboss.hal.testsuite.fragment.FormFragment;
import org.jboss.hal.testsuite.fragment.TableFragment;
import org.jboss.hal.testsuite.page.configuration.ElytronOtherSettingsPage;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.operations.Operations;
import org.wildfly.extras.creaper.core.online.operations.Values;

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
import static org.jboss.hal.dmr.ModelDescriptionConstants.SEARCH_PATH;
import static org.jboss.hal.dmr.ModelDescriptionConstants.TYPE;
import static org.jboss.hal.dmr.ModelDescriptionConstants.URL;
import static org.jboss.hal.dmr.ModelDescriptionConstants.VALUE;
import static org.jboss.hal.resources.Ids.ELYTRON_CREDENTIAL_STORE;
import static org.jboss.hal.resources.Ids.ELYTRON_KEY_STORE;
import static org.jboss.hal.resources.Ids.ELYTRON_LDAP_KEY_STORE;
import static org.jboss.hal.resources.Ids.TAB;
import static org.jboss.hal.testsuite.test.configuration.elytron.ElytronFixtures.*;

@RunWith(Arquillian.class)
public class StoresSettingsTest {

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

    // --------------- credential store

    @Test
    public void credentialStoreCreate() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, CREDENTIAL_STORE_ITEM);
        TableFragment table = page.getCredentialStoreTable();

        crud.create(credentialStoreAddress(CRED_ST_CREATE), table, f -> {
            f.text(NAME, CRED_ST_CREATE);
            f.flip(CREATE, true);
            f.text(LOCATION, ANY_STRING);
            f.text(CLEAR_TEXT, ANY_STRING);
        });
    }

    @Test
    public void credentialStoreTryCreate() {
        console.verticalNavigation().selectSecondary(STORES_ITEM, CREDENTIAL_STORE_ITEM);
        TableFragment table = page.getCredentialStoreTable();

        crud.createWithErrorAndCancelDialog(table, f -> {
            f.text(NAME, CRED_ST_CREATE);
            f.flip(CREATE, true);
        }, CLEAR_TEXT);
    }

    @Test
    public void credentialStoreUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, CREDENTIAL_STORE_ITEM);
        TableFragment table = page.getCredentialStoreTable();
        FormFragment form = page.getCredentialStoreForm();
        table.bind(form);
        table.select(CRED_ST_UPDATE);
        page.getCredentialStoreTab().select(Ids.build(ELYTRON_CREDENTIAL_STORE, ATTRIBUTES, TAB));
        crud.update(credentialStoreAddress(CRED_ST_UPDATE), form, PROVIDER_NAME, ANY_STRING);
    }

    @Test
    public void credentialStoreCredentialReferenceUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, CREDENTIAL_STORE_ITEM);
        TableFragment table = page.getCredentialStoreTable();
        FormFragment form = page.getCredentialStoreCredentialReferenceForm();
        table.bind(form);
        table.select(CRED_ST_UPDATE);
        page.getCredentialStoreTab().select(Ids.build(ELYTRON_CREDENTIAL_STORE, CREDENTIAL_REFERENCE, TAB));
        crud.update(credentialStoreAddress(CRED_ST_UPDATE), form, f -> f.text(CLEAR_TEXT, ANY_STRING),
                ver -> ver.verifyAttribute(CREDENTIAL_REFERENCE + PROPERTY_DELIMITER + CLEAR_TEXT, ANY_STRING));
    }

    @Test
    public void credentialStoreDelete() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, CREDENTIAL_STORE_ITEM);
        TableFragment table = page.getCredentialStoreTable();

        crud.delete(credentialStoreAddress(CRED_ST_DELETE), table, CRED_ST_DELETE);
    }

    // --------------- filtering key store

    @Test
    public void filteringKeyStoreCreate() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, FILTERING_KEY_STORE_ITEM);
        TableFragment table = page.getFilteringKeyStoreTable();

        crud.create(filteringKeyStoreAddress(FILT_ST_CREATE), table, f -> {
            f.text(NAME, FILT_ST_CREATE);
            f.text(ALIAS_FILTER, ANY_STRING);
            f.text(KEY_STORE, KEY_ST_UPDATE);
        });
    }

    @Test
    public void filteringKeyStoreTryCreate() {
        console.verticalNavigation().selectSecondary(STORES_ITEM, FILTERING_KEY_STORE_ITEM);
        TableFragment table = page.getFilteringKeyStoreTable();

        crud.createWithErrorAndCancelDialog(table, f -> {
            f.text(NAME, FILT_ST_CREATE);
            f.text(ALIAS_FILTER, ANY_STRING);
        }, KEY_STORE);
    }

    @Test
    public void filteringKeyStoreUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, FILTERING_KEY_STORE_ITEM);
        TableFragment table = page.getFilteringKeyStoreTable();
        FormFragment form = page.getFilteringKeyStoreForm();
        table.bind(form);
        table.select(FILT_ST_UPDATE);

        crud.update(filteringKeyStoreAddress(FILT_ST_UPDATE), form, ALIAS_FILTER);
    }

    @Test
    public void filteringKeyStoreDelete() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, FILTERING_KEY_STORE_ITEM);
        TableFragment table = page.getFilteringKeyStoreTable();

        crud.delete(filteringKeyStoreAddress(FILT_ST_DELETE), table, FILT_ST_DELETE);
    }

    // --------------- key store

    @Test
    public void keyStoreCreate() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, KEY_STORE_ITEM);
        TableFragment table = page.getKeyStoreTable();

        crud.create(keyStoreAddress(KEY_ST_CREATE), table, f -> {
            f.text(NAME, KEY_ST_CREATE);
            f.text(TYPE, JKS);
            f.text(CLEAR_TEXT, ANY_STRING);
        });
    }

    @Test
    public void keyStoreTryCreate() {
        console.verticalNavigation().selectSecondary(STORES_ITEM, KEY_STORE_ITEM);
        TableFragment table = page.getKeyStoreTable();

        crud.createWithErrorAndCancelDialog(table, f -> f.text(NAME, KEY_ST_CREATE), TYPE);
    }

    @Test
    public void keyStoreUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, KEY_STORE_ITEM);
        page.getKeyStoreTab().select(Ids.build(ELYTRON_KEY_STORE, ATTRIBUTES, TAB));
        TableFragment table = page.getKeyStoreTable();
        FormFragment form = page.getKeyStoreForm();
        table.bind(form);
        table.select(KEY_ST_UPDATE);
        crud.update(keyStoreAddress(KEY_ST_UPDATE), form, PATH);
    }

    @Test
    public void keyStoreCredentialReferenceUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, KEY_STORE_ITEM);
        TableFragment table = page.getKeyStoreTable();
        FormFragment form = page.getKeyStoreCredentialReferenceForm();
        table.bind(form);
        table.select(KEY_ST_CR_UPDATE);
        page.getKeyStoreTab().select(Ids.build(ELYTRON_KEY_STORE, CREDENTIAL_REFERENCE, TAB));
        crud.update(keyStoreAddress(KEY_ST_UPDATE), form, f -> f.text(CLEAR_TEXT, ANY_STRING),
                ver -> ver.verifyAttribute(CREDENTIAL_REFERENCE + PROPERTY_DELIMITER + CLEAR_TEXT, ANY_STRING));
    }

    @Test
    public void keyStoreDelete() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, KEY_STORE_ITEM);
        TableFragment table = page.getKeyStoreTable();

        crud.delete(keyStoreAddress(KEY_ST_DELETE), table, KEY_ST_DELETE);
    }

    // --------------- ldap key store

    @Test
    public void ldapKeyStoreCreate() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, LDAP_KEY_STORE_ITEM);
        TableFragment table = page.getLdapKeyStoreTable();

        crud.create(ldapKeyStoreAddress(LDAPKEY_ST_CREATE), table, f -> {
            f.text(NAME, LDAPKEY_ST_CREATE);
            f.text(DIR_CONTEXT, DIR_UPDATE);
            f.text(SEARCH_PATH, ANY_STRING);
        });
    }

    @Test
    public void ldapKeyStoreTryCreate() {
        console.verticalNavigation().selectSecondary(STORES_ITEM, LDAP_KEY_STORE_ITEM);
        TableFragment table = page.getLdapKeyStoreTable();

        crud.createWithErrorAndCancelDialog(table, f -> f.text(NAME, LDAPKEY_ST_CREATE), DIR_CONTEXT);
    }

    @Test
    public void ldapKeyStoreUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, LDAP_KEY_STORE_ITEM);
        TableFragment table = page.getLdapKeyStoreTable();
        FormFragment form = page.getLdapKeyStoreForm();
        table.bind(form);
        table.select(LDAPKEY_ST_UPDATE);
        page.getLdapKeyStoreTab().select(Ids.build(ELYTRON_LDAP_KEY_STORE, TAB));

        crud.update(ldapKeyStoreAddress(LDAPKEY_ST_UPDATE), form, FILTER_ALIAS);
    }

    @Test
    public void ldapKeyStoreDelete() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, LDAP_KEY_STORE_ITEM);
        TableFragment table = page.getLdapKeyStoreTable();

        crud.delete(ldapKeyStoreAddress(LDAPKEY_ST_DELETE), table, LDAPKEY_ST_DELETE);
    }

    @Test
    public void ldapKeyStoreNewItemTemplateTryAdd() {
        console.verticalNavigation().selectSecondary(STORES_ITEM, LDAP_KEY_STORE_ITEM);
        TableFragment table = page.getLdapKeyStoreTable();
        FormFragment form = page.getLdapKeyStoreNewItemTemplateForm();
        table.bindBlank(form);
        table.select(LDAPKEY_ST_TEMP4_TRY_ADD);
        page.getLdapKeyStoreTab().select(Ids.build(ELYTRON_LDAP_KEY_STORE, NEW_ITEM_TEMPLATE, TAB));
        EmptyState emptyState = form.emptyState();
        emptyState.mainAction();

        AddResourceDialogFragment addResource = console.addResourceDialog();
        addResource.getForm().text(NEW_ITEM_PATH, ANY_STRING);
        addResource.getForm().text(NEW_ITEM_RDN, ANY_STRING);
        addResource.getPrimaryButton().click();
        try {
            addResource.getForm().expectError(NEW_ITEM_ATTRIBUTES);
        } finally {
            addResource.getSecondaryButton().click(); // close dialog to cleanup
        }
    }

    @Test
    public void ldapKeyStoreNewItemTemplateAdd() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, LDAP_KEY_STORE_ITEM);
        TableFragment table = page.getLdapKeyStoreTable();
        FormFragment form = page.getLdapKeyStoreNewItemTemplateForm();
        table.bindBlank(form);
        table.select(LDAPKEY_ST_TEMP3_ADD);
        page.getLdapKeyStoreTab().select(Ids.build(ELYTRON_LDAP_KEY_STORE, NEW_ITEM_TEMPLATE, TAB));

        String rndName = "p1";
        String rndValue = Random.name();
        ModelNode props = new ModelNode();
        props.get(NAME).set(rndName);
        props.get(VALUE).add(rndValue);
        ModelNode newItemTemplate = new ModelNode();
        newItemTemplate.get(NEW_ITEM_PATH).set(ANY_STRING);
        newItemTemplate.get(NEW_ITEM_RDN).set(ANY_STRING);
        newItemTemplate.get(NEW_ITEM_ATTRIBUTES).add(props);

        crud.createSingleton(ldapKeyStoreAddress(LDAPKEY_ST_TEMP3_ADD), form, f -> {
            f.text(NEW_ITEM_PATH, ANY_STRING);
            f.text(NEW_ITEM_RDN, ANY_STRING);
            f.list(NEW_ITEM_ATTRIBUTES).add(rndName, rndValue);
        }, verifier -> verifier.verifyAttribute(NEW_ITEM_TEMPLATE, newItemTemplate));
    }

    @Test
    public void ldapKeyStoreNewItemTemplateUpdate() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, LDAP_KEY_STORE_ITEM);
        TableFragment table = page.getLdapKeyStoreTable();
        FormFragment form = page.getLdapKeyStoreNewItemTemplateForm();
        table.bind(form);
        table.select(LDAPKEY_ST_TEMP1_UPDATE);
        page.getLdapKeyStoreTab().select(Ids.build(ELYTRON_LDAP_KEY_STORE, NEW_ITEM_TEMPLATE, TAB));

        String rndValue = Random.name();

        crud.update(ldapKeyStoreAddress(LDAPKEY_ST_TEMP1_UPDATE), form, f -> f.text(NEW_ITEM_RDN, rndValue),
                verifier -> verifier.verifyAttribute(NEW_ITEM_TEMPLATE + PROPERTY_DELIMITER + NEW_ITEM_RDN, rndValue));
    }

    @Test
    public void ldapKeyStoreNewItemTemplateRemove() throws Exception {
        console.verticalNavigation().selectSecondary(STORES_ITEM, LDAP_KEY_STORE_ITEM);
        TableFragment table = page.getLdapKeyStoreTable();
        FormFragment form = page.getLdapKeyStoreNewItemTemplateForm();
        table.bind(form);
        table.select(LDAPKEY_ST_TEMP2_DELETE);
        page.getLdapKeyStoreTab().select(Ids.build(ELYTRON_LDAP_KEY_STORE, NEW_ITEM_TEMPLATE, TAB));

        crud.deleteSingleton(ldapKeyStoreAddress(LDAPKEY_ST_TEMP2_DELETE), form,
                verifier -> verifier.verifyAttributeIsUndefined(NEW_ITEM_TEMPLATE));
    }
}
