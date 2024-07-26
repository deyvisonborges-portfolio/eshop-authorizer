package com.deyvisonborges.eshop.authorizer.app.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class UserStoreConfig {
  @Bean
  UserDetailsService userDetailsService() {
    final var userDetails = new InMemoryUserDetailsManager();
    userDetails.createUser(
      User.withUsername("user")
      .password("{noop}password")
      .build() 
    );
		return userDetails;
  }
}
