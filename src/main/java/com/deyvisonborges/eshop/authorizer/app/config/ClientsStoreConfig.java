package com.deyvisonborges.eshop.authorizer.app.config;

import java.util.UUID;
import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

@Configuration
public class ClientsStoreConfig {
  @Bean
  RegisteredClientRepository registeredClientRepository() {
    RegisteredClient reactClient = RegisteredClient
      .withId(UUID.randomUUID().toString())
      .clientId("react-client-id")
      .clientSecret("{noop}react-client-secret")
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .redirectUri("http://127.0.0.1:3000/login/oauth2/code/react-client")
      .postLogoutRedirectUri("http://127.0.0.1:3000/")
      .scope(OidcScopes.OPENID)
      .scope("read")
      .scope("write")
      .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
      .build();

    RegisteredClient apiClient = RegisteredClient
      .withId(UUID.randomUUID().toString())
      .clientId("api-client-id")
      .clientSecret("{noop}api-client-secret")
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .scope("read")
      .scope("write")
      .build();

    RegisteredClient oidcClient = RegisteredClient
      .withId(UUID.randomUUID().toString())
      .clientId("client-server-id")
      .clientSecret("{noop}secret")
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .redirectUri("http://127.0.0.1:9001/login/oauth2/code/client-server-oidc")
      .postLogoutRedirectUri("http://127.0.0.1:9001/")
      .scope(OidcScopes.OPENID)
      .scope(OidcScopes.PROFILE)
      .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
      .build();
    
    return new InMemoryRegisteredClientRepository(Arrays.asList(reactClient, apiClient, oidcClient));
  }
}
