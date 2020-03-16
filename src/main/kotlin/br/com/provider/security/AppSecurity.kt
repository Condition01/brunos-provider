package br.com.provider.security

import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter

@EnableWebSecurity
@Configuration
class AppSecurity: WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity?) {
//        super.configure(http)
        http
                ?.antMatcher("/**")
                ?.authorizeRequests()
                ?.antMatchers("/**")?.authenticated()
                ?.and()
                ?.formLogin()?.loginPage("/saml/sp/select")
    }
}