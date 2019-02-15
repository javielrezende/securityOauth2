package com.javielrezende.securityoauth2.token;

import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Esta classe foi criada para quando a requisicao de novo acces token for enviada e retornada o refresh_token
 * este refresh nao ficara disponivel no body da requisicao, mas sim em um cookie de um HTTPS
 * Para isso, milesimos de segundos ates dessa requisicao ser enviada, interceptamos o refresh
 * e nao deixaremos que seja disponivel no body
 *
 * O obj OAuth2AccessToken é o tipo do dado que se quer interceptar
 */
@ControllerAdvice
public class RefreshTokenPostProcessor implements ResponseBodyAdvice<OAuth2AccessToken> {

    /**
     * O método beforeBodyWrite somente irá processar quando este método retornar true
     * portanto quando o nome do método de retorno for igual ao descrito
     * @param returnType
     * @param converterType
     * @return
     */
    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return returnType.getMethod().getName().equals("postAccesToken");
    }

    /**
     * Este método que recupera o corpo da requisição e adiciona-se ao cookie
     * E remove o refreshToken do body
     *
     * o req é utilizado para pegar a requisicao para adicionar o contextPath no metodo adicionarRefreshTokenNoCookie
     * o res é utilziado para adicionar o cookie na requisicao no metodo adicionarRefreshTokenNoCookie
     *
     * Feito um cast no body para acessar o metodo de retirar o refresh_token do body no metodo removerRefreshTokenDoBody
     * ]
     * @param body
     * @param returnType
     * @param selectedContentType
     * @param selectedConverterType
     * @param request
     * @param response
     * @return
     */
    @Override
    public OAuth2AccessToken beforeBodyWrite(OAuth2AccessToken body, MethodParameter returnType, MediaType selectedContentType, Class<? extends HttpMessageConverter<?>> selectedConverterType, ServerHttpRequest request, ServerHttpResponse response) {

        HttpServletRequest req = ((ServletServerHttpRequest)request).getServletRequest();
        HttpServletResponse resp = ((ServletServerHttpResponse)response).getServletResponse();

        DefaultOAuth2AccessToken token = (DefaultOAuth2AccessToken)body;

        String refreshToken = body.getRefreshToken().getValue();

        adicionarRefreshTokenNoCookie(refreshToken, req, resp);
        removerRefreshTokenDoBody(token);

        return null;
    }

    /**
     * setHttpOnly utilizado somente em http
     * setMaxAge tempo em dias para o cookie durar
     * resp.addCookie(refreshTokenCookie) adiciona o cookie na resposta
     *
     * @param refreshToken
     * @param req
     * @param resp
     */
    private void adicionarRefreshTokenNoCookie(String refreshToken, HttpServletRequest req, HttpServletResponse resp) {
        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);

        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false); //Mudar para producao
        refreshTokenCookie.setPath(req.getContextPath() + "/oauth/token");
        refreshTokenCookie.setMaxAge(2592000);
        resp.addCookie(refreshTokenCookie);

    }


    private void removerRefreshTokenDoBody(DefaultOAuth2AccessToken token) {
        token.setRefreshToken(null);
    }

}
