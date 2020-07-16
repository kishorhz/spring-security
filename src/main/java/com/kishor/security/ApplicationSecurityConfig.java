package com.kishor.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.kishor.auth.ApplicationUserService;
import com.kishor.jwt.JwtConfig;
import com.kishor.jwt.JwtTokenVerifier;
import com.kishor.jwt.JwtUsernameAndPasswordAuthenticationFilter;

import static com.kishor.security.ApplicationUserRole.STUDENT;

import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

	private final PasswordEncoder passwordEncoder;
	private final SecretKey secretKey;
	private final JwtConfig jwtConfig;
	
	@Autowired
	private UserDetailsService applicationUserService;

	
	  @Autowired 
	  public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
			  ApplicationUserService applicationUserService,
			  SecretKey secretKey,
			  JwtConfig jwtConfig){ 
		  
		  this.passwordEncoder = passwordEncoder; 
		  this.applicationUserService = applicationUserService;
		  this.secretKey = secretKey;
		  this.jwtConfig = jwtConfig;
		  }
	  
	 
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			
			/* jwt configuration */
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
			.addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
			/* jwt configuration end*/
			.authorizeRequests()
			.antMatchers("/", "/welcome.html").permitAll()
			.antMatchers("/api/**").hasRole(STUDENT.name())
			.anyRequest()
			.authenticated()
			/* for the form based atuthentication.
			.and()
			.formLogin()
				.loginPage("/login")
				.permitAll()
				.defaultSuccessUrl("/courses", true)
				.usernameParameter("username")
				.passwordParameter("password")
			.and()
			.rememberMe()
				.tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
				.key("somethingverysecured")
				.rememberMeParameter("remember-me")
			.and()
			.logout()
				.logoutUrl("/logout")
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
				.clearAuthentication(true)
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID","remember-me")
				.logoutSuccessUrl("/login")
				*/
			;
		
		}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}
	
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
	}

	/*
	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails kishorUser = User.builder()
				.username("kishor")
				.password(passwordEncoder.encode("password"))
//				.roles(ADMIN.name())// ROLE_ADMIN
				.authorities(ADMIN.getGrantedAuthorities())
				.build();
		
		UserDetails nayanUser = User.builder()
				.username("nayan")
				.password(passwordEncoder.encode("password123"))
//				.roles(STUDENT.name())// ROLE_STUDENT
				.authorities(STUDENT.getGrantedAuthorities())
				.build();

		UserDetails mohanUser = User.builder()
				.username("mohan")
				.password(passwordEncoder.encode("password123"))
//				.roles(ADMINTRAINEE.name())// ROLE_ADMINTRAINEE
				.authorities(ADMINTRAINEE.getGrantedAuthorities())
				.build();
		return new InMemoryUserDetailsManager(
				kishorUser,
				nayanUser,
				mohanUser
				);
	}

*/
}
