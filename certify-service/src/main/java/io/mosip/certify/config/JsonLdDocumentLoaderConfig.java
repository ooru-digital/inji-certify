/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.config;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import foundation.identity.jsonld.ConfigurableDocumentLoader;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.CollectionUtils;

import java.io.InputStream;
import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Provides a JSON-LD {@link DocumentLoader} for VC signing / URDNA2015
 * canonicalization that resolves well-known contexts from an in-memory local
 * cache (bundled in data-integrity-java / ld-signatures-java and optional
 * classpath static files) instead of fetching {@code www.w3.org} on every sign.
 * <p>
 * Under parallel bulk issuance, live remote context fetches are unreliable;
 * local resolution of {@code https://www.w3.org/ns/credentials/v2} (and other
 * standard suites) removes that dependency. Optional HTTPS remains available
 * for issuer-specific domain contexts, with a stamped-out remote cache.
 */
@Configuration
@Slf4j
public class JsonLdDocumentLoaderConfig {

    @Value("${mosip.certify.jsonld.enable-https:true}")
    private boolean enableHttps;

    @Value("${mosip.certify.jsonld.enable-http:false}")
    private boolean enableHttp;

    @Value("${mosip.certify.jsonld.remote-cache-max-size:200}")
    private long remoteCacheMaxSize;

    @Value("${mosip.certify.jsonld.remote-cache-expire-hours:24}")
    private long remoteCacheExpireHours;

    /**
     * Optional map of context URI → Spring resource location for additional
     * static contexts (e.g. domain vocabularies). Example:
     * {@code {'https://example.org/ctx.json':'classpath:jsonld-contexts/example.jsonld'}}
     */
    @Value("#{${mosip.certify.jsonld.static-contexts:{}}}")
    private Map<String, String> staticContexts;

    private final ResourceLoader resourceLoader;

    public JsonLdDocumentLoaderConfig(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Bean
    public DocumentLoader certifyDocumentLoader() {
        Map<URI, JsonDocument> localCache = new HashMap<>();
        localCache.putAll(DataIntegrityContexts.CONTEXTS);
        localCache.putAll(LDSecurityContexts.CONTEXTS);
        loadStaticContexts(localCache);

        ConfigurableDocumentLoader loader = new ConfigurableDocumentLoader(localCache);
        loader.setEnableLocalCache(true);
        loader.setEnableHttps(enableHttps);
        loader.setEnableHttp(enableHttp);
        loader.setEnableFile(false);

        if (enableHttps || enableHttp) {
            Cache<URI, Document> remoteCache = Caffeine.newBuilder()
                    .maximumSize(remoteCacheMaxSize)
                    .expireAfterWrite(Duration.ofHours(remoteCacheExpireHours))
                    .build();
            loader.setRemoteCache(remoteCache);
            log.info("JSON-LD document loader: local contexts={}, https={}, http={}, remoteCacheMaxSize={}",
                    localCache.size(), enableHttps, enableHttp, remoteCacheMaxSize);
            return new StampedeSafeDocumentLoader(loader);
        }

        log.info("JSON-LD document loader: local contexts={}, https=false, http=false (offline mode)",
                localCache.size());
        return loader;
    }

    private void loadStaticContexts(Map<URI, JsonDocument> localCache) {
        if (CollectionUtils.isEmpty(staticContexts)) {
            return;
        }
        for (Map.Entry<String, String> entry : staticContexts.entrySet()) {
            URI contextUri = URI.create(entry.getKey());
            String location = entry.getValue();
            try {
                Resource resource = resourceLoader.getResource(location);
                try (InputStream in = resource.getInputStream()) {
                    JsonDocument document = JsonDocument.of(MediaType.JSON_LD, in);
                    document.setDocumentUrl(contextUri);
                    localCache.put(contextUri, document);
                    log.info("Loaded static JSON-LD context {} from {}", contextUri, location);
                }
            } catch (Exception e) {
                throw new IllegalStateException(
                        "Failed to load static JSON-LD context " + contextUri + " from " + location, e);
            }
        }
    }

    /**
     * Prevents thundering-herd remote fetches for the same context URI under
     * parallel bulk issuance when HTTPS fallback is enabled.
     */
    static final class StampedeSafeDocumentLoader implements DocumentLoader {

        private final ConfigurableDocumentLoader delegate;
        private final ConcurrentHashMap<URI, Object> locks = new ConcurrentHashMap<>();

        StampedeSafeDocumentLoader(ConfigurableDocumentLoader delegate) {
            this.delegate = delegate;
        }

        @Override
        public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {
            if (delegate.isEnableLocalCache() && delegate.getLocalCache().containsKey(url)) {
                return delegate.getLocalCache().get(url);
            }
            if (delegate.getRemoteCache() != null) {
                Document cached = delegate.getRemoteCache().getIfPresent(url);
                if (cached != null) {
                    return cached;
                }
            }
            Object lock = locks.computeIfAbsent(url, u -> new Object());
            synchronized (lock) {
                try {
                    if (delegate.getRemoteCache() != null) {
                        Document cached = delegate.getRemoteCache().getIfPresent(url);
                        if (cached != null) {
                            return cached;
                        }
                    }
                    return delegate.loadDocument(url, options);
                } finally {
                    locks.remove(url, lock);
                }
            }
        }
    }
}
