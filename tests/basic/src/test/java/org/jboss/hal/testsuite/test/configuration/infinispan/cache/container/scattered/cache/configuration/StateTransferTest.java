package org.jboss.hal.testsuite.test.configuration.infinispan.cache.container.scattered.cache.configuration;

import java.io.IOException;

import org.jboss.arquillian.core.api.annotation.Inject;
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.hal.testsuite.Console;
import org.jboss.hal.testsuite.CrudOperations;
import org.jboss.hal.testsuite.Random;
import org.jboss.hal.testsuite.creaper.ManagementClientProvider;
import org.jboss.hal.testsuite.fragment.FormFragment;
import org.jboss.hal.testsuite.page.configuration.ScatteredCachePage;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
import org.wildfly.extras.creaper.core.online.operations.OperationException;
import org.wildfly.extras.creaper.core.online.operations.Operations;

import static org.jboss.hal.dmr.ModelDescriptionConstants.JGROUPS;
import static org.jboss.hal.dmr.ModelDescriptionConstants.TRANSPORT;
import static org.jboss.hal.testsuite.test.configuration.infinispan.InfinispanFixtures.cacheContainerAddress;
import static org.jboss.hal.testsuite.test.configuration.infinispan.InfinispanFixtures.scatteredCacheAddress;
import static org.jboss.hal.testsuite.test.configuration.infinispan.InfinispanFixtures.stateTransferAddress;

@RunWith(Arquillian.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class StateTransferTest {

    private static final OnlineManagementClient client = ManagementClientProvider.createOnlineManagementClient();
    private static final Operations operations = new Operations(client);

    private static final String CACHE_CONTAINER = "cache-container-" + Random.name();
    private static final String SCATTERED_CACHE_STATE_TRANSFER = "scattered-cache-" + Random.name();

    @BeforeClass
    public static void setUp() throws IOException, OperationException {
        operations.add(cacheContainerAddress(CACHE_CONTAINER));
        operations.add(cacheContainerAddress(CACHE_CONTAINER).and(TRANSPORT, JGROUPS));
        operations.add(scatteredCacheAddress(CACHE_CONTAINER, SCATTERED_CACHE_STATE_TRANSFER));
        operations.removeIfExists(stateTransferAddress(CACHE_CONTAINER, SCATTERED_CACHE_STATE_TRANSFER));
    }

    @AfterClass
    public static void tearDown() throws IOException, OperationException {
        try {
            operations.removeIfExists(cacheContainerAddress(CACHE_CONTAINER));
        } finally {
            client.close();
        }
    }

    @Inject private CrudOperations crud;
    @Inject private Console console;
    @Page private ScatteredCachePage page;
    private FormFragment form;

    @Before
    public void initPage() {
        page.navigate(CACHE_CONTAINER, SCATTERED_CACHE_STATE_TRANSFER);
        console.verticalNavigation().selectPrimary("scattered-cache-item");
        form = page.getStateTransferForm();
    }

    @Test
    public void create() throws Exception {
        crud.createSingleton(stateTransferAddress(CACHE_CONTAINER, SCATTERED_CACHE_STATE_TRANSFER), form);
    }

    @Test
    public void remove() throws Exception {
        crud.deleteSingleton(stateTransferAddress(CACHE_CONTAINER, SCATTERED_CACHE_STATE_TRANSFER), form);
    }

    @Test
    public void editChunkSize() throws Exception {
        crud.update(stateTransferAddress(CACHE_CONTAINER, SCATTERED_CACHE_STATE_TRANSFER), form, "chunk-size", 123);
    }

    @Test
    public void editTimeout() throws Exception {
        crud.update(stateTransferAddress(CACHE_CONTAINER, SCATTERED_CACHE_STATE_TRANSFER), form, "timeout", 789L);
    }
}
