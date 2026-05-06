/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.spring;

import io.github.davidalmeidac.sealedenv.SealedEnv;
import io.github.davidalmeidac.sealedenv.core.SealedEnvException;

import org.apache.commons.logging.Log;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.boot.logging.DeferredLog;
import org.springframework.context.ApplicationListener;
import org.springframework.boot.context.event.ApplicationPreparedEvent;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Reads the {@code .env.sealed} file at the earliest possible Spring Boot
 * lifecycle stage — before {@code @ConfigurationProperties} binding — and
 * exposes the decrypted values as a Spring {@link MapPropertySource}.
 *
 * <p>This runs as an {@link EnvironmentPostProcessor} so that even properties
 * referenced by {@code @Value} on autoconfigured beans see the decrypted
 * values. It does NOT mutate {@link System#getenv()} (immutable in JVM) nor
 * {@link System#getProperties()}; values are only visible through the Spring
 * {@code Environment}.
 *
 * <p>Registered via {@code META-INF/spring.factories}.
 */
public class SealedEnvEnvironmentPostProcessor
        implements EnvironmentPostProcessor, ApplicationListener<ApplicationPreparedEvent> {

    /**
     * Spring Boot uses {@link DeferredLog} during EnvironmentPostProcessor
     * because the real logger is not yet initialised. We replay messages
     * once {@link ApplicationPreparedEvent} fires.
     */
    private static final DeferredLog LOG = new DeferredLog();

    private static final String PROPERTY_SOURCE_NAME = "sealedEnv";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment,
                                       SpringApplication application) {
        SealedEnvProperties props = Binder.get(environment)
                .bind("sealed-env", Bindable.of(SealedEnvProperties.class))
                .orElseGet(SealedEnvProperties::new);

        if (!props.isEnabled()) {
            LOG.debug("sealed-env: disabled via configuration");
            return;
        }

        Path path = Path.of(props.getPath());
        if (!Files.isRegularFile(path)) {
            String msg = "sealed-env: file not found at " + path.toAbsolutePath();
            if (props.isFailFast()) {
                throw new SealedEnvException(SealedEnvException.Code.CONFIG_ERROR, msg);
            }
            LOG.debug(msg + " — skipping");
            return;
        }

        try {
            SealedEnv.LoadOptions opts = new SealedEnv.LoadOptions();
            opts.path = path;
            opts.populateSystem = false;
            opts.masterKeyVar = props.getMasterKeyVar();
            opts.signingKeyVar = props.getSigningKeyVar();
            opts.unsealTokenVar = props.getUnsealTokenVar();
            opts.deployIdVar = props.getDeployIdVar();

            Map<String, String> decrypted = SealedEnv.loadSealed(opts);
            MapPropertySource source = new MapPropertySource(
                    PROPERTY_SOURCE_NAME, java.util.Collections.unmodifiableMap(
                    new java.util.LinkedHashMap<>(decrypted)));

            if (props.isOverride()) {
                environment.getPropertySources().addFirst(source);
            } else {
                environment.getPropertySources().addLast(source);
            }
            LOG.info("sealed-env: loaded " + decrypted.size() + " values from " + path);
        } catch (SealedEnvException e) {
            if (props.isFailFast()) throw e;
            LOG.warn("sealed-env: failed to load (" + e.code() + "): " + e.getMessage()
                    + " — continuing without sealed values");
        }
    }

    @Override
    public void onApplicationEvent(ApplicationPreparedEvent event) {
        Log realLogger = org.apache.commons.logging.LogFactory.getLog(
                SealedEnvEnvironmentPostProcessor.class);
        LOG.replayTo(realLogger);
    }
}
