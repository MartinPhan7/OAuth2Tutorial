package com.tutorial.oauth2authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	//	GET http://localhost:9000/.well-known/oauth-authorization-server
//	GET http://localhost:9000/oauth2/jwks
//	POST http://localhost:9000/oauth2/token     grant_type=authorization_code&client_id=client&client_secret=secret&code=code&redirect_uri=https://oauthdebugger.com/debug with HttpBasic Authen
//	POST http://localhost:9000/oauth2/introspect     token = access_token
//  POST http://localhost:9000/oauth2/revoke     token = access_token

	@Bean
	@Order(1)
	public SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(withDefaults());
		http.exceptionHandling(e -> e
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
		return http.build();

	}

	@Bean
	@Order(2)
	public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
		return http
			.formLogin(withDefaults())
			.authorizeHttpRequests(authorize ->
				authorize.anyRequest().authenticated())
			.build();

	}

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user1 = User.withUsername("user")
			.password("{noop}password")
			.authorities("read")
			.build();
		return new InMemoryUserDetailsManager(user1);
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId("client")
			.clientSecret("{noop}secret")
			.scope("read")
			.redirectUri("https://oidcdebugger.com/debug")
			.redirectUri("https://oauthdebugger.com/debug")
			.redirectUri("https://springone.io/authorized")
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.build();

		return new InMemoryRegisteredClientRepository(registeredClient);
	}

}
