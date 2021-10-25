package com.naren.spring.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

  @Override
  public void init(WebSecurity web) throws Exception {
    super.init(web);
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    super.configure(web);
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    // Set your configuration on the auth object
    auth.inMemoryAuthentication()
        .withUser("naren")
        .password("naren")
        .roles("READER")
        .and()
        .withUser("josh")
        .password("josh")
        .roles("WRITER");
  }

  @Bean
  public PasswordEncoder getPasswordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .antMatchers("/write")
        .hasRole("WRITER")
        .antMatchers("/read")
        .hasAnyRole("WRITER", "READER")
        .antMatchers("/")
        .permitAll()
        .and()
        .formLogin();
  }
}
