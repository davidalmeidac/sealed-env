/*
 * Copyright (c) 2026 David Almeida
 * SPDX-License-Identifier: MIT
 */
package io.github.davidalmeidac.sealedenv.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the {@code sealed-env} Spring Boot starter.
 *
 * <p>All settings are under the {@code sealed-env} prefix in
 * {@code application.properties} / {@code application.yml}.
 */
@ConfigurationProperties(prefix = "sealed-env")
public class SealedEnvProperties {

    /**
     * Whether the starter is active. When false, no decryption is attempted.
     * Default: {@code true} — but only takes effect if the file exists.
     */
    private boolean enabled = true;

    /**
     * Path to the {@code .env.sealed} file, relative to the working directory.
     * Default: {@code .env.sealed}.
     */
    private String path = ".env.sealed";

    /**
     * If true, missing key material or a missing file is treated as a fatal
     * startup error. If false (default in dev), the application starts with a
     * warning and any missing env vars surface as normal property-resolution
     * errors. Set to {@code true} in production.
     */
    private boolean failFast = false;

    /**
     * If true, decrypted values are placed at the highest precedence so they
     * override application properties. Default: {@code false} — explicit
     * properties win, matching dotenv conventions.
     */
    private boolean override = false;

    /** Environment variable holding the master key (hex or base64). */
    private String masterKeyVar = "SEALED_ENV_KEY";

    /** Environment variable holding the signing key for team/enterprise modes. */
    private String signingKeyVar = "SEALED_ENV_SIGNING_KEY";

    /** Environment variable holding the unseal token for enterprise mode. */
    private String unsealTokenVar = "SEALED_ENV_UNSEAL_TOKEN";

    /** Environment variable holding the deploy id when CHALLENGE-BIND is enabled. */
    private String deployIdVar = "SEALED_ENV_DEPLOY_ID";

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public boolean isFailFast() { return failFast; }
    public void setFailFast(boolean failFast) { this.failFast = failFast; }

    public boolean isOverride() { return override; }
    public void setOverride(boolean override) { this.override = override; }

    public String getMasterKeyVar() { return masterKeyVar; }
    public void setMasterKeyVar(String masterKeyVar) { this.masterKeyVar = masterKeyVar; }

    public String getSigningKeyVar() { return signingKeyVar; }
    public void setSigningKeyVar(String signingKeyVar) { this.signingKeyVar = signingKeyVar; }

    public String getUnsealTokenVar() { return unsealTokenVar; }
    public void setUnsealTokenVar(String unsealTokenVar) { this.unsealTokenVar = unsealTokenVar; }

    public String getDeployIdVar() { return deployIdVar; }
    public void setDeployIdVar(String deployIdVar) { this.deployIdVar = deployIdVar; }
}
