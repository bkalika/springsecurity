package net.proselyte.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import net.proselyte.springsecurity.security.JwtConfigurer;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	private final JwtConfigurer jwtConfigurer;
	
//	private final UserDetailsService userDetailsService;
	
//	@Autowired
//	public SecurityConfig(@Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService) {
//		this.userDetailsService = userDetailsService;
//	}
	
	public SecurityConfig(JwtConfigurer jwtConfigurer) {
		super();
		this.jwtConfigurer = jwtConfigurer;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.authorizeRequests()
			.antMatchers("/").permitAll()
			.antMatchers("/api/v1/auth/login").permitAll()
			.anyRequest()
			.authenticated()
			.and()
//			.formLogin()
//			.loginPage("/auth/login").permitAll()
//			.defaultSuccessUrl("/auth/success")
//			.and()
//			.logout()
//			.logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout", "POST"))
//			.invalidateHttpSession(true)
//			.clearAuthentication(true)
//			.deleteCookies("JSESSIONID")
//			.logoutSuccessUrl("/auth/login");
			.apply(jwtConfigurer);
	}

//	@Bean
//	@Override
//	protected UserDetailsService userDetailsService() {
//		return new InMemoryUserDetailsManager(
//				User.builder()
//					.username("admin")
//					.password(passwordEncoder().encode("admin"))
//					.authorities(Role.ADMIN.getAuthorities())
//					.build(),
//
//				User.builder()
//					.username("user")
//					.password(passwordEncoder().encode("user"))
//					.authorities(Role.USER.getAuthorities())
//					.build()
//		);
//	}
	

//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.authenticationProvider(daoAuthenticationProvider());
//	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}
	
//	@Bean
//	protected DaoAuthenticationProvider daoAuthenticationProvider() {
//		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
//		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
//		daoAuthenticationProvider.setUserDetailsService(userDetailsService);
//		return daoAuthenticationProvider;
//	}
	
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

}
