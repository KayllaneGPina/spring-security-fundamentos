# Autenticação com Spring Security



Repositório dedicado a aprender Spring Security.



1. # Autenticação Simples

Autenticação em memória basicamente  permite criar mais de usuários e perfis de acesso. A classe **WebSecurityConfigurerAdapter** descontinuada pelo o Spring e agora o **InMemoryUserDetailsManager** do Spring Security implementa a interface **UserDetailsService** para fornecer o suporte para username/password. Então o que antes era assim: 

```
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
                .withUser("user")
                .password("{noop}user123")
                .roles("USERS")
                .and()
                .withUser("admin")
                .password("{noop}master123")
                .roles("MANAGERS");
    }
}
```



Fica assim:

```
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class WebSecurtiyConfig {

    @Bean
    public UserDetailsService user() {
        UserDetails user = User.builder()
                .username("user")
                .password("{noop}user123")
                .roles("USERS")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}admin123")
                .roles("USERS", "MANAGERS")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }
}
```



2. ## Referência de Pesquisas

   - ***[Spring Security without the WebSecurityConfigurerAdapter](https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter)***
   - ***[In-Memory Authentication :: Spring Security](https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/in-memory.html#page-title)***



---

1. ## Configure Adapter

   Novamente, a classe **WebSecurityConfigurerAdapter** foi descontinuada pelo Spring e agora para fazer a configuração de múltiplas URL's usamos a classe **SecurityFilterChain**. Exemplo:

   

```
@Bean
public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity.authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/").permitAll()
                    .requestMatchers(HttpMethod.POST, "/login").permitAll()
                    .requestMatchers("/managers").hasAnyRole("MANAGERS")
                    .requestMatchers("/users").hasAnyRole("USERS", "MANAGERS")
                    .anyRequest().authenticated()
            )
            .formLogin(withDefaults())
            .httpBasic(withDefaults());

    return httpSecurity.build();

}
```

2. ## HttpSecurity

   - Um **HttpSecurity** permite configurar segurança baseada na web para solicitações http específicas. Por padrão, ele será aplicado a todas as requisições, mas pode ser restringido usando **RequestMatcher** ou outros métodos semelhantes.

     