/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.spring;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Auto-configuration entry point.
 *
 * <p>The actual decryption happens in
 * {@link SealedEnvEnvironmentPostProcessor}, which runs much earlier than
 * regular auto-configuration so that decrypted values are visible to all
 * other beans during binding. This class exists primarily to register
 * {@link SealedEnvProperties} with Spring's metadata processor (so users
 * get IDE autocompletion in {@code application.yml}).
 */
@AutoConfiguration
@EnableConfigurationProperties(SealedEnvProperties.class)
public class SealedEnvAutoConfiguration {
}
