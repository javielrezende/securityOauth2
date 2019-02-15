package com.javielrezende.securityoauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

@Configuration
@EnableAuthorizationServer
public class AutorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    /**
     * Responsavel por pegar o usuario e senha
     */
    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * Autoriza a aplicacao cliente a utilizar o authentication server
     * @param clients da acesso a metodos para configuracao
     * @throws Exception
     *
     * secret == senha
     * accessTokenValiditySeconds == 30 minutos == 1800 segundos
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("angular")
                .secret("@ngul@r0")
                .scopes("read", "write")
                .authorizedGrantTypes("password")
                .accessTokenValiditySeconds(1800);
    }

    /**
     * Utilizado para armazenar o token
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .tokenStore(tokenStore())
                .authenticationManager(authenticationManager);
    }

    @Bean
    public TokenStore tokenStore() {
        return new InMemoryTokenStore();
    }


}
