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
package org.jboss.hal.testsuite.test.configuration.modcluster;

import org.jboss.arquillian.core.api.annotation.Inject;
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.hal.testsuite.Console;
import org.jboss.hal.testsuite.CrudOperations;
import org.jboss.hal.testsuite.Random;
import org.jboss.hal.testsuite.creaper.ManagementClientProvider;
import org.jboss.hal.testsuite.fragment.FormFragment;
import org.jboss.hal.testsuite.fragment.TableFragment;
import org.jboss.hal.testsuite.page.configuration.ModclusterPage;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.operations.Batch;
import org.wildfly.extras.creaper.core.online.operations.Operations;
import org.wildfly.extras.creaper.core.online.operations.Values;

import static org.jboss.hal.dmr.ModelDescriptionConstants.CONNECTOR;
import static org.jboss.hal.dmr.ModelDescriptionConstants.DEFAULT;
import static org.jboss.hal.dmr.ModelDescriptionConstants.NAME;
import static org.jboss.hal.dmr.ModelDescriptionConstants.TYPE;
import static org.jboss.hal.testsuite.test.configuration.modcluster.ModclusterFixtures.*;
import static org.junit.runners.MethodSorters.NAME_ASCENDING;

@RunWith(Arquillian.class)
@FixMethodOrder(NAME_ASCENDING)
public class LoadMetricTest {

    private static final OnlineManagementClient client = ManagementClientProvider.createOnlineManagementClient();
    private static final Operations operations = new Operations(client);

    @BeforeClass
    public static void beforeClass() throws Exception {
        Batch proxyAdd = new Batch();
        proxyAdd.add(proxyAddress(PROXY_UPDATE), Values.of(CONNECTOR, DEFAULT));
        proxyAdd.add(dynamicLoadProviderAddress(PROXY_UPDATE));
        operations.batch(proxyAdd);
        operations.add(loadMetricAddress(PROXY_UPDATE, LOAD_MET_DELETE), Values.of(TYPE, "mem"));
        operations.add(loadMetricAddress(PROXY_UPDATE, LOAD_MET_UPDATE), Values.of(TYPE, "mem"));
    }

    @AfterClass
    public static void afterClass() throws Exception {
        operations.remove(proxyAddress(PROXY_UPDATE));
    }

    @Inject private Console console;
    @Inject private CrudOperations crud;
    @Page private ModclusterPage page;
    private TableFragment table;
    private FormFragment form;

    @Before
    public void setUp() throws Exception {
        page.navigate(NAME, PROXY_UPDATE);
        console.verticalNavigation().selectPrimary("load-metrics-item");
        table = page.getLoadMetricsTable();
        form = page.getLoadMetricsForm();
        table.bind(form);
    }

    @Test
    public void create() throws Exception {
        crud.create(loadMetricAddress(PROXY_UPDATE, LOAD_MET_CREATE), table, f -> {
                    f.text(NAME, LOAD_MET_CREATE);
                    f.select(TYPE, "cpu");
                },
                ver -> ver.verifyAttribute(TYPE, "cpu"));
    }

    @Test
    public void reset() throws Exception {
        table.select(LOAD_MET_UPDATE);
        crud.reset(loadMetricAddress(PROXY_UPDATE, LOAD_MET_UPDATE), form);
    }

    @Test
    public void update() throws Exception {
        table.select(LOAD_MET_UPDATE);
        crud.update(loadMetricAddress(PROXY_UPDATE, LOAD_MET_UPDATE), form, WEIGHT, Random.number());
    }

    @Test
    public void updateCapacity() throws Exception {
        // update an attribute of type DOUBLE
        table.select(LOAD_MET_UPDATE);
        crud.update(loadMetricAddress(PROXY_UPDATE, LOAD_MET_UPDATE), form, "capacity", Random.numberDouble());
    }

    @Test
    public void zzzDelete() throws Exception {
        crud.delete(loadMetricAddress(PROXY_UPDATE, LOAD_MET_DELETE), table, LOAD_MET_DELETE);
    }
}