package com.javielrezende.securityoauth2.token;

import org.apache.catalina.util.ParameterMap;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;
import java.util.Map;

/**
 * @Order(Ordered.HIGHEST_PRECEDENCE) é um filtro com prioridade muito alta, pois
 * esta requisicao deve ser analisada antes de tudo
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RefreshTokenCookiePreProcessorFilter implements Filter {

    /**
     * if utilizado para saber se eh uma rota de refresh cookie,
     * pois verifica ali todos os parametros passados por esta requisicao
     * Se for ele pega o valor deste cookie para jogar para dentro da requisicao
     *
     * O problema é: quando ele recebe este cookie, é porque logicamente a requisicao ja foi feita, onde
     * o cookie recebido nao pode ser inserido no body, pois esta requisicao aconteceu à milisegundos
     * atras, de modo que pegamos este cookie
     *
     * Para isso criamos uma classe chamada MyServletRequestWrapper que refaz o mapa da requisicao
     * passando o refresh token no parametro da requisicao, pois nao havia antes
     * @param request
     * @param response
     * @param chain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;

        if ("/oauth/token".equalsIgnoreCase(req.getRequestURI())
                && "refresh_token".equals(req.getParameter("grant_type"))
                && req.getCookies() != null) {

            for (Cookie cookie : req.getCookies()) {
                if(cookie.getName().equals("refreshToken")){
                    String refreshToken = cookie.getValue();

                    req = new MyServletRequestWrapper(req, refreshToken);
                }
            }

        }

        chain.doFilter(req, response);

    }


    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }


    @Override
    public void destroy() {

    }


    static class MyServletRequestWrapper extends HttpServletRequestWrapper {

        private String refreshToken;


        public MyServletRequestWrapper(HttpServletRequest request, String refreshToken) {
            super(request);
            this.refreshToken = refreshToken;
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            ParameterMap<String, String[]> map = new ParameterMap<>(getRequest().getParameterMap());
            map.put("refresh_token", new String[] { refreshToken });
            map.setLocked(true);
            return map;
        }
    }

}
