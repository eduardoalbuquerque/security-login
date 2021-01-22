package com.solucitiva.solucitiva.auth.auth;

import com.nimbusds.jose.shaded.json.parser.JSONParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.GsonHttpMessageConverter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.text.ParseException;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//        if(!isValid("6Lf72TQaAAAAAJFe2JG9P0nhmmdsrQefiddKkUdt")){
//            return;
//        }
        clients
                .inMemory()
                .withClient("contabil-web")
                .secret(passwordEncoder.encode("web123"))
                .authorizedGrantTypes("password", "refresh_token")
                .scopes("write", "read")
                .accessTokenValiditySeconds(6 * 60 * 60)// 6 horas
                .refreshTokenValiditySeconds(60 * 24 * 60 * 60) // 60 dias

                .and()
                .withClient("foodanalytics")
                .secret(passwordEncoder.encode("food123"))
                .authorizedGrantTypes("authorization_code")
                .scopes("write", "read")
                .redirectUris("http://www.foodanalytics.local:8082")

                .and()
                .withClient("faturamento")
                .secret(passwordEncoder.encode("faturamento123"))
                .authorizedGrantTypes("client_credentials")
                .scopes("write", "read")

                .and()
                .withClient("checktoken")
                .secret(passwordEncoder.encode("check123"));
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("isAuthenticated()");
        security.checkTokenAccess("permitAll()");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .reuseRefreshTokens(false);
    }

    public boolean isValid(String clientRecaptchaResponse) throws IOException, ParseException, JSONException {
        final String RECAPTCHA_SERVICE_URL = "https://www.google.com/recaptcha/api/siteverify";
        final String SECRET_KEY = "6Lf72TQaAAAAAI2lW3dkZXCOpzuDy5cYAWIBPxDo";

        if(clientRecaptchaResponse == null || "".equals(clientRecaptchaResponse)){
            return false;
        }

        //conecta a url do google
        URL url = new URL(RECAPTCHA_SERVICE_URL);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

        String postParams =
                "secret=" + SECRET_KEY +
                "&response=" + clientRecaptchaResponse;

        //enviar POST para o google reCAPTCHA sever
        connection.setDoOutput(true);
        DataOutputStream dataOutputStream = new DataOutputStream(connection.getOutputStream());
        dataOutputStream.writeBytes(postParams);
        dataOutputStream.flush();
        dataOutputStream.close();

        int responseCode = connection.getResponseCode();

        //apagar - apenas para visualizar no console
        System.out.println("Post parameters: " + postParams);
        System.out.println("Response Code: " + responseCode);

        BufferedReader in = new BufferedReader(new InputStreamReader(
                connection.getInputStream()));

        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        //apagar - apenas para visualizar no console
        System.out.println(response.toString());

        System.out.println(response.toString());

        //Parse JSON-response
        JSONObject jsonObject = new JSONObject(response.toString());

        Boolean success = (Boolean) jsonObject.get("success");
        Double score = (Double) jsonObject.get("score");

        System.out.println("success : " + success);
        System.out.println("score : " + score);

        //result should be sucessfull and spam score above 0.5
        return (success && score >= 0.5);

    }

}