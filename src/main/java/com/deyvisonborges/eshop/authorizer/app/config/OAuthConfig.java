package com.deyvisonborges.eshop.authorizer.app.config;

import java.time.Duration;
import java.util.Arrays;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

@Configuration
public class OAuthConfig {
  @Bean
  AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

  @Bean
  RegisteredClientRepository clientRepository() {
    PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    // CLIENT_SECRET_BASIC with CLIENT_CREDENTIALS
    RegisteredClient clientSecretBasicClientCredentials = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("client-secret-basic-client-credentials")
        .clientSecret(passwordEncoder.encode("secret"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(false)
            .build())
        .build();

    // CLIENT_SECRET_POST with CLIENT_CREDENTIALS
    RegisteredClient clientSecretPostClientCredentials = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("client-secret-post-client-credentials")
        .clientSecret(passwordEncoder.encode("secret"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(false)
            .build())
        .build();

    // CLIENT_SECRET_JWT with CLIENT_CREDENTIALS
    RegisteredClient clientSecretJwtClientCredentials = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("client-secret-jwt-client-credentials")
        .clientSecret(passwordEncoder.encode("secret"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(false)
            .build())
        .build();

    // PRIVATE_KEY_JWT with CLIENT_CREDENTIALS
    RegisteredClient privateKeyJwtClientCredentials = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("private-key-jwt-client-credentials")
        .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(false)
            .build())
        .build();

    // NONE with CLIENT_CREDENTIALS
    RegisteredClient noneClientCredentials = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("none-client-credentials")
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(false)
            .build())
        .build();

    // TLS_CLIENT_AUTH with CLIENT_CREDENTIALS
    RegisteredClient tlsClientAuthClientCredentials = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("tls-client-auth-client-credentials")
        .clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(false)
            .build())
        .build();

    // SELF_SIGNED_TLS_CLIENT_AUTH with CLIENT_CREDENTIALS
    RegisteredClient selfSignedTlsClientAuthClientCredentials = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("self-signed-tls-client-auth-client-credentials")
        .clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(false)
            .build())
        .build();

    // CLIENT_SECRET_BASIC with AUTHORIZATION_CODE
    RegisteredClient clientSecretBasicAuthorizationCode = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("client-secret-basic-authorization-code")
        .clientSecret(passwordEncoder.encode("secret"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("https://example.com/callback")
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();

    // CLIENT_SECRET_POST with AUTHORIZATION_CODE
    RegisteredClient clientSecretPostAuthorizationCode = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("client-secret-post-authorization-code")
        .clientSecret(passwordEncoder.encode("secret"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("https://example.com/callback")
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();

    // CLIENT_SECRET_JWT with AUTHORIZATION_CODE
    RegisteredClient clientSecretJwtAuthorizationCode = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("client-secret-jwt-authorization-code")
        .clientSecret(passwordEncoder.encode("secret"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("https://example.com/callback")
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();

    // PRIVATE_KEY_JWT with AUTHORIZATION_CODE
    RegisteredClient privateKeyJwtAuthorizationCode = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("private-key-jwt-authorization-code")
        .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("https://example.com/callback")
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();

    // TLS_CLIENT_AUTH with AUTHORIZATION_CODE
    RegisteredClient tlsClientAuthAuthorizationCode = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("tls-client-auth-authorization-code")
        .clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("https://example.com/callback")
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();

    // SELF_SIGNED_TLS_CLIENT_AUTH with AUTHORIZATION_CODE
    RegisteredClient selfSignedTlsClientAuthAuthorizationCode = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("self-signed-tls-client-auth-authorization-code")
        .clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("https://example.com/callback")
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();

    // CLIENT_SECRET_BASIC with REFRESH_TOKEN
    RegisteredClient clientSecretBasicRefreshToken = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("client-secret-basic-refresh-token")
        .clientSecret(passwordEncoder.encode("secret"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();

    // CLIENT_SECRET_POST with REFRESH_TOKEN
    RegisteredClient clientSecretPostRefreshToken = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("client-secret-post-refresh-token")
        .clientSecret(passwordEncoder.encode("secret"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();

    // CLIENT_SECRET_JWT with REFRESH_TOKEN
    RegisteredClient clientSecretJwtRefreshToken = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("client-secret-jwt-refresh-token")
        .clientSecret(passwordEncoder.encode("secret"))
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();

    // PRIVATE_KEY_JWT with REFRESH_TOKEN
    RegisteredClient privateKeyJwtRefreshToken = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("private-key-jwt-refresh-token")
        .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();

    // TLS_CLIENT_AUTH with REFRESH_TOKEN
    RegisteredClient tlsClientAuthRefreshToken = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("tls-client-auth-refresh-token")
        .clientAuthenticationMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();

    // SELF_SIGNED_TLS_CLIENT_AUTH with REFRESH_TOKEN
    RegisteredClient selfSignedTlsClientAuthRefreshToken = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("self-signed-tls-client-auth-refresh-token")
        .clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .scope("scope1")
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(10))
            .build())
        .clientSettings(ClientSettings.builder()
            .requireAuthorizationConsent(true)
            .build())
        .build();

    return new InMemoryRegisteredClientRepository(
        Arrays.asList(
            clientSecretBasicClientCredentials,
            clientSecretPostClientCredentials,
            clientSecretJwtClientCredentials,
            privateKeyJwtClientCredentials,
            noneClientCredentials,
            tlsClientAuthClientCredentials,
            selfSignedTlsClientAuthClientCredentials,
            clientSecretBasicAuthorizationCode,
            clientSecretPostAuthorizationCode,
            clientSecretJwtAuthorizationCode,
            privateKeyJwtAuthorizationCode,
            tlsClientAuthAuthorizationCode,
            selfSignedTlsClientAuthAuthorizationCode,
            clientSecretBasicRefreshToken,
            clientSecretPostRefreshToken,
            clientSecretJwtRefreshToken,
            privateKeyJwtRefreshToken,
            tlsClientAuthRefreshToken,
            selfSignedTlsClientAuthRefreshToken));
  }
}
