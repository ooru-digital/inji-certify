/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.config;

import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import foundation.identity.jsonld.JsonLDObject;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.DefaultResourceLoader;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

/**
 * Verifies W3C / security suite contexts resolve from the local cache without
 * contacting www.w3.org, including under parallel bulk-style load.
 */
public class JsonLdDocumentLoaderConfigTest {

    private DocumentLoader documentLoader;

    @Before
    public void setUp() throws Exception {
        JsonLdDocumentLoaderConfig config = new JsonLdDocumentLoaderConfig(new DefaultResourceLoader());
        setField(config, "enableHttps", false);
        setField(config, "enableHttp", false);
        setField(config, "remoteCacheMaxSize", 200L);
        setField(config, "remoteCacheExpireHours", 24L);
        setField(config, "staticContexts", Collections.emptyMap());
        documentLoader = config.certifyDocumentLoader();
    }

    @Test
    public void loadsCredentialsV2FromLocalCache() throws Exception {
        URI credentialsV2 = URI.create("https://www.w3.org/ns/credentials/v2");
        Document document = documentLoader.loadDocument(credentialsV2, new DocumentLoaderOptions());
        assertNotNull("credentials/v2 must resolve from local cache", document);
        assertEquals(credentialsV2, document.getDocumentUrl());
    }

    @Test
    public void loadsCredentialsV1AndSecuritySuitesFromLocalCache() throws Exception {
        DocumentLoaderOptions options = new DocumentLoaderOptions();
        assertNotNull(documentLoader.loadDocument(
                URI.create("https://www.w3.org/2018/credentials/v1"), options));
        assertNotNull(documentLoader.loadDocument(
                URI.create("https://w3id.org/security/suites/ed25519-2020/v1"), options));
        assertNotNull(documentLoader.loadDocument(
                URI.create("https://w3id.org/security/data-integrity/v2"), options));
        assertEquals(DataIntegrityContexts.CONTEXTS.size() > 0, true);
    }

    @Test
    public void parallelNormalizeCredentialsV2DoesNotRequireNetwork() throws Exception {
        String vcJson = """
                {
                  "@context": ["https://www.w3.org/ns/credentials/v2"],
                  "type": ["VerifiableCredential"],
                  "issuer": "did:example:issuer",
                  "validFrom": "2024-01-01T00:00:00Z",
                  "credentialSubject": { "id": "did:example:subject" }
                }
                """;

        int[] batchSizes = {50, 100, 150};
        for (int batchSize : batchSizes) {
            assertParallelNormalize(vcJson, batchSize);
        }
    }

    private void assertParallelNormalize(String vcJson, int parallelism) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(32, parallelism));
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(parallelism);
        AtomicInteger failures = new AtomicInteger();
        List<String> errors = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < parallelism; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    JsonLDObject jsonLDObject = JsonLDObject.fromJson(vcJson);
                    jsonLDObject.setDocumentLoader(documentLoader);
                    String normalized = jsonLDObject.normalize("urdna2015");
                    if (normalized == null || normalized.isBlank()) {
                        failures.incrementAndGet();
                        errors.add("empty normalized form");
                    }
                } catch (Exception e) {
                    failures.incrementAndGet();
                    errors.add(e.getClass().getSimpleName() + ": " + e.getMessage());
                } finally {
                    done.countDown();
                }
            });
        }

        start.countDown();
        assertTrue("timed out for batch " + parallelism, done.await(60, TimeUnit.SECONDS));
        pool.shutdownNow();
        assertEquals("batch " + parallelism + " failures: " + errors, 0, failures.get());
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field field = JsonLdDocumentLoaderConfig.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }
}
