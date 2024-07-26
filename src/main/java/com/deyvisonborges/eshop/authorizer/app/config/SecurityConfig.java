package com.deyvisonborges.eshop.authorizer.app.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityFilterChain oauth2Chain(final HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    
    http
      .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			  .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0

    http
      .exceptionHandling((exceptions) -> exceptions
        .defaultAuthenticationEntryPointFor(
          new LoginUrlAuthenticationEntryPoint("/login"),
          new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
        ))
        .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults())
      );  
    return http.build();
  }

  @Bean
  SecurityFilterChain defaultChain(final HttpSecurity http) throws Exception{
    http.authorizeHttpRequests((authorize) -> authorize.requestMatchers("/test").permitAll());
    http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());
    http.formLogin(Customizer.withDefaults());
    return http.build();
  }
}
