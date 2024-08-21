package com.tutorial.oauth2resourceserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	// Postman tests
	// Generate a OAuth2 access token
	// Configure
	/*
	*   Grant Type = "Authorization Code"
	*   Callback URL = "https://oauthdebugger.com/debug"
	*   Auth URL = "http://localhost:9000/oauth2/authorize"
	*   Access Token URL = "http://localhost:9000/oauth2/token"
	*   Client ID = "client"
	*   Client Secret = "secret"
	*   Scope = "read"
	*   Client Authentication Method = "client_secret_basic"
	*
	* Then
	*
	*   Put access token in Authorization header with Bearer prefix
	*   and send request to resource server with http://localhost:8080 once authenticated.
	*   Before :401 Unauthorized / After :200 OK
	* */

	@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
	private String issuerUri;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
			.authorizeHttpRequests(requests ->
				requests.anyRequest().authenticated())
			.oauth2ResourceServer(oauth2 ->
				oauth2.jwt(jwt ->
						jwt.decoder(JwtDecoders.fromIssuerLocation(issuerUri))))
			.build();
	}
}
