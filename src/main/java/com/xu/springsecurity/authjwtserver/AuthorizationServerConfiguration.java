package com.xu.springsecurity.authjwtserver;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @program: authjwtserver
 * @description:
 **/

@EnableAuthorizationServer
@Configuration
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
    AuthenticationManager authenticationManager;
    KeyPair keyPair;
    boolean jwtEnabled;

    public AuthorizationServerConfiguration(
            AuthenticationConfiguration authenticationConfiguration,
            KeyPair keyPair,
            @Value("${security.oauth2.authorizationserver.jwt.enabled:true}")boolean jwtEnabled) throws Exception {
        this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
        this.keyPair = keyPair;
        this.jwtEnabled = jwtEnabled;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("reader")
                .authorizedGrantTypes("password")
                .secret("{noop}secret")
                .scopes("message:read")
                .accessTokenValiditySeconds(600_000_000)
                .and()
                .withClient("writer")
                .authorizedGrantTypes("password")
                .secret("{noop}secret")
                .scopes("message:write")
                .accessTokenValiditySeconds(600_000_000)
                .and()
                .withClient("noscopes")
                .authorizedGrantTypes("password")
                .secret("{noop}secret")
                .scopes("none")
                .accessTokenValiditySeconds(600_000_000);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
                .authenticationManager(this.authenticationManager)
                .tokenStore(tokenStore());
        if (this.jwtEnabled) {
            endpoints
                    .accessTokenConverter(accessTokenConverter());
        }
    }
    @Bean
    public TokenStore tokenStore() {
        if (this.jwtEnabled) {
            return new JwtTokenStore(accessTokenConverter());
        } else {
            return new InMemoryTokenStore();
        }
    }
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
       converter.setKeyPair(this.keyPair);
        //converter.setSigningKey("secretly");//不安全的密钥
       // converter.setSigningKey("P8CjKSfWJJ7yWVM2QrzcVFACT-mZCAT1W7l4dXE3D3Ll5ji78zC5Nk2bivRHJfcIhc_Zepgtd80oUPB9pQ2raGh47FdQ4xCQAzcG1h5xV9bkFM68zFYOmGNf572oQ8E3kIHIOLBVh1kJZ0XfHj3dAcWUqQOjPft47SF_q5fTPkxG3N-eUTuK6qyjrxhCXHywZiLBv8Ax3TUmqq4Sqaydx7tHVGI3gb13PwaLxRHFeJAF9mMw5O8tJWZ0t7RL--m1q6SNNyDzFR-4OEIIR2s4K68ORD9Sd08cLEnUnuHKUHpaog22JnL6VVW9f6cAK41EW5A_zsmldpJM90y-S0abp3I");

        DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
        accessTokenConverter.setUserTokenConverter((UserAuthenticationConverter) new SubjectAttributeUserTokenConverter());
        converter.setAccessTokenConverter(accessTokenConverter);

        return converter;
    }
}

@Configuration
class    UserConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .mvcMatchers("/.well-known/jwks.json").permitAll()
                .anyRequest().authenticated()
                .and()
                .httpBasic()
                .and()
                .csrf().ignoringRequestMatchers(request -> "/introspect".equals(request.getRequestURI()));
    }

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withDefaultPasswordEncoder()
                .username("subject")
                .password("password")
                .roles("USER")
                .build()
        );
    }
}


@FrameworkEndpoint
class IntrospectEndpoint {
    TokenStore tokenStore;

    IntrospectEndpoint(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    @PostMapping("/introspect")
    @ResponseBody
    public Map<String, Object> introspect(@RequestParam("token") String token) {
        OAuth2AccessToken accessToken = this.tokenStore.readAccessToken(token);
        Map<String, Object> attributes = new HashMap<>();
        if (accessToken == null || accessToken.isExpired()) {
            attributes.put("active", false);
            return attributes;
        }

        OAuth2Authentication authentication = this.tokenStore.readAuthentication(token);

        attributes.put("active", true);
        attributes.put("exp", accessToken.getExpiration().getTime());
        attributes.put("scope", accessToken.getScope().stream().collect(Collectors.joining(" ")));
        attributes.put("sub", authentication.getName());

        return attributes;
    }
}

/**
 * Legacy Authorization Server (spring-security-oauth2) does not support any
 * <a href target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> endpoint.
 *
 * This class adds ad-hoc support in order to better support the other samples in the repo.
 */
@FrameworkEndpoint
class JwkSetEndpoint {
    KeyPair keyPair;

    JwkSetEndpoint(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    @GetMapping("/.well-known/jwks.json")
    @ResponseBody
    public Map<String, Object> getKey() {
        RSAPublicKey publicKey = (RSAPublicKey) this.keyPair.getPublic();
        RSAKey key = new RSAKey.Builder(publicKey).build();
        return new JWKSet(key).toJSONObject();
    }
}

/**
 * An Authorization Server will more typically have a key rotation strategy, and the keys will not
 * be hard-coded into the application code.
 *
 * For simplicity, though, this sample doesn't demonstrate key rotation.
 */
@Configuration
class KeyConfig {

    @Bean
    KeyPair keyPair() throws IOException, ParseException, JOSEException {
        JWKSet localKeys = JWKSet.load(new File("src/main/resources/newprivateKeySet.json"));
        List<JWK> matches = new JWKSelector(
                new JWKMatcher.Builder()
                .keyType(KeyType.RSA)
                .keyID("845d94b2-d2fa-4334-b344-5ed064bddf4d")
                .build()).select(localKeys);
        JWK rsaJWK = matches.get(0);
        RSAKey rsaKey = rsaJWK.toRSAKey();
        KeyPair keyPair = rsaKey.toKeyPair();
        return keyPair;
    }


   /* @Bean
    KeyPair keyPair() {

        try {

            JWK jwk = JWK.parseFromPEMEncodedObjects("-----BEGIN PRIVATE KEY-----\n" +
                    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDK5AhKMdL8Vse/\n" +
                    "0qT0ZmPtymak584oe6TlLprcNQvKI/rXeQNiPJU+EYyDTxpGrOo1hMM9zSMcoIyg\n" +
                    "qgmw8/RC37XFypZDGAqx8wWLjKlDyJigK2SA0f2U2Xl1BRv2tXKWlWUHe7XTySWe\n" +
                    "P7p9ZbM3weEgaZny0l7hqkUlJSTMy1fHE59RpJHIMP8NR1NFx7JmiFUUf2vvQwJn\n" +
                    "WF3LwdQa1DAyAEDIbGFLrbfouKMAcAOi370f3JKWhfaH7WF49StBgOgmAGNzTOPw\n" +
                    "ZPehtXaKbOAS+kvtV6MxVN7oC6kViRMhB+RQZjzA3ReQlSRyRjdIakqocc51NrT7\n" +
                    "LWe4ZbAtAgMBAAECggEBAKQNvqY/o1pm0R1KNhdos2STRGwTA5+4Wpz2EkH8oovQ\n" +
                    "jAOu1g2Y7xRBHF0QmS6MotSjhTtzo/CB4TQISc3LdLaeLVzBcr7NsdgxqUotcrBc\n" +
                    "gw0ACUQgh+rT7mGwv+u8y+r24borTdrxynkrDqBWm5N6MY8D1HeDozTVeROP9TGh\n" +
                    "yNNi7gyu8tPIz3c3pUIQv1TInG1H/y8ca3rpwF9sRUUAsJQ5N6IIkFeEF9BV1czu\n" +
                    "So1sLZ3GLntq9+0eEmEDN4T+qyoMRTSipo7ao9MBiV2OwFqY70T+TzxMVTx7h0Ss\n" +
                    "WEYOfy99AzOV7s0NHMMWlvnrSQ7uLIQ5dF7AeiDCZAECgYEA9OuEZwEhzYC7Eq4r\n" +
                    "NJx7zrF94kqcIs6m4r7kLj6HdIz1mwcwTn6UIQs7Ioa6/5dMsYQsuUfDsXSsPmuP\n" +
                    "TSiJAUQhqx9WwDIzUHP4nItMRrpWGNMDERKWnw/CDZs8f3OekLyH8lrPi+QLVBYL\n" +
                    "8t/3H1utlrwP5bRAPxZcqLj2u5MCgYEA1BHDdtkHGPsdU/I+nDfgSd0yGD+CTEMa\n" +
                    "wixe4Axk3Ne8AUddLxClTWQ2rvIoHuoLtbI46dM1kub7yjxqcu1hiI8K6LuS1uH9\n" +
                    "TzpA03JdnC8zFAkecqvZCMt9FyHAnPSG0F8Oc4PUSCAZU7I1NEafC3pUfsXHCFsP\n" +
                    "OwhswttGvT8CgYA1mBf4BkpkUsgc9VnlAF0jRLm8PAFgqIHiWk1KRUqU2YehLfiH\n" +
                    "JLG7bV66VmszJOOWcMrsnGSZP2O1oQnRo44fZc5MSOZN1m5eK5J6hwzg6UOP2RTx\n" +
                    "tnSZR/R5z790UFOhbm/9O5vxC6zi8JQayKGmDgS1WF/OLxxj8bvC+/6Z2wKBgGVb\n" +
                    "dBuqkNzcsGC96DTL8/P5t4alXAZNEE373QCii9aNebr2u8/R2d/KZORqsshLvnsC\n" +
                    "CnefTfy/T1qSU6JIWJRnIaSoef8gFey2/+LPx3PtjzElRpsyDVJJx6i1phSePoz6\n" +
                    "0bJeMKikRtac1xb8JenbduT8bCtPMlFZrnnXSdELAoGAClNtYvFQCNVw9YWxSqBi\n" +
                    "Ek+bsP7n5noNHlR4JHeThIG52H+NJBJBGBVv/w4L2zGTwjnqJqor+J0O4kT8iJES\n" +
                    "JzvNQw4dZfdAjreL8wqXFGrP+K87rx8xJwyt1GgZZPrxEI6aXdQkMxJD7r6qxyWM\n" +
                    "EioxZ/slxV596Yye088nJIE=\n" +
                    "-----END PRIVATE KEY-----");
            JWK jwk1 = JWK.parseFromPEMEncodedObjects("-----BEGIN PRIVATE KEY-----\n" +
                    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCMsLyZrdpaXsdy\n" +
                    "E4VHio7dAXcnW656CeeAwjmwWxFr7u1PNCBK/HLKFes9j0GnmzIqLdKjCklKA1gU\n" +
                    "vjriDL9VbMLwScDCZSFlP4yROwU35IlETh9An6VcE96QkX/Wq0udBeuZBYfWIg/y\n" +
                    "UB4uiOgSEh4BlpFYZ1Z9zxbnuRL/iYy5HTLKLT05mPDAWVi8h89fcnFBB9WhXjlP\n" +
                    "98BcFKYOUwJD+ruaBiCpZaGNfHBksQ5xirdNdctmwjtrAzNuQwnfz1+p3af7N5G+\n" +
                    "jwejwqf5R05wqVqxtGbdBkAFGx9A8C0n80s5Dzd+qxSOBj6sG4XaReaRj+vM6F37\n" +
                    "2i3Q62VPAgMBAAECggEAIlxP06C4QXYAdAX8eRqIBcYD2eL0W+3rUnEdMcssGBZE\n" +
                    "cyGh+W5qgpyT1XcVa9/lgpOqbBNpDuB+NKK5Mtg2KqDjg1gf8dpNK7M3m4i0n4/7\n" +
                    "TmleDKRw+GoJ43kFpeI0F2eIwNiu8kdjaaTTmj3pn/A4z958JQEoCJX5XCLBVxNe\n" +
                    "LlB0kJBec7pze8mQEm8bKD3ahzQrs/h9np3Fqln9KKjafqF83dFfyl36b3J6lQR+\n" +
                    "j61faVRduVbYS0FpuWWmUSKebeclRqnGfNCJrGC9d3+gzsI5ltLj4dxGYBL12Fx7\n" +
                    "dPTkH1qHY2mgrBoAxqIlLgu/4WiMHTtc7eNm77jUsQKBgQDHyNYhFF0FPROGN4mN\n" +
                    "rsQWa/3hJ6AwMT0GzYoncbQPDjTitvsII5Mi8BNxHzttUKCuUdALfCNAlfBirniQ\n" +
                    "G/V6gBVQCPNd0d3xdVxUjHbtnJ5wFsHJWhhkHlnRaLF0lCSdzbnwRpr4pDwjj4QM\n" +
                    "Ua/mxqWCfTSsQ8Pmm0Gdq5Pk4wKBgQC0RyWYfcmUt9QWVpLj6JNc9sQSoBhdjwbo\n" +
                    "4yto3hl006+mc9MV9wFP34zoBN7vs6KJENsW7yu5VLqpQ8Jw/cz5DLwlsSPRN8q3\n" +
                    "oLNpWBCd21i71HdQ9zCdnmUotix5lZEOi7Q0NKipeF+2t2NxMw93iVPYRf626yFM\n" +
                    "A3k7zrjVpQKBgQDDZqBgfE06yXDmLj2gUNXC5F7Mr/gSCqaYl8HPMHue2hNJxxQh\n" +
                    "8sF/Q3aQhq6WDW0K8kPcZ88G5V/W9LRApsfix5GQ1SBKm/BKsLHclAHiBvRDx05E\n" +
                    "RJVknvbURWSDFD34BfYdlsEN/XxAf6b0cZTsz0+kIBe7gRAC5ck4kE83ZwKBgFNG\n" +
                    "Ph6XlEMnO0fqS8YNS+z4bA/yde7Zv6ZaMVYqqfWmRxALlqkhxTBhIlSW02hEQUMx\n" +
                    "TxLj/f2JHwRLMYlCI6mzcUGz9siRDgoOqHFz5ZEVnoJ9HXSACqv0W+QXaqnrJetj\n" +
                    "KyWmYXaPDR94zO2gWXetLtbLVmKmcGYNgLXYwtalAoGATyzNq8cwGhCqYzTdPjaI\n" +
                    "O10Gungm+NLlkgMY86qIogsuj/09B44hvhMzZ+nnrALOpwRpohLvHn6oTIKmsC5G\n" +
                    "s+BSX3+xlaM903m19Pea8O6j0Ys8hBCf71bCTJV6l7IbABV2OT7sToXBRGhjdoZD\n" +
                    "lO4Skn5Irq+2KizqcL2dd1c=\n" +
                    "-----END PRIVATE KEY-----");


            RSAKey rsaKey = jwk.toRSAKey();
            KeyPair keyPair = rsaKey.toKeyPair();
            return keyPair;
        } catch (JOSEException e) {
            e.printStackTrace();
            throw new IllegalArgumentException(e);
        }
        *//*
        try {


            String privateExponent = "3851612021791312596791631935569878540203393691253311342052463788814433805390794604753109719790052408607029530149004451377846406736413270923596916756321977922303381344613407820854322190592787335193581632323728135479679928871596911841005827348430783250026013354350760878678723915119966019947072651782000702927096735228356171563532131162414366310012554312756036441054404004920678199077822575051043273088621405687950081861819700809912238863867947415641838115425624808671834312114785499017269379478439158796130804789241476050832773822038351367878951389438751088021113551495469440016698505614123035099067172660197922333993";
            String modulus = "18044398961479537755088511127417480155072543594514852056908450877656126120801808993616738273349107491806340290040410660515399239279742407357192875363433659810851147557504389760192273458065587503508596714389889971758652047927503525007076910925306186421971180013159326306810174367375596043267660331677530921991343349336096643043840224352451615452251387611820750171352353189973315443889352557807329336576421211370350554195530374360110583327093711721857129170040527236951522127488980970085401773781530555922385755722534685479501240842392531455355164896023070459024737908929308707435474197069199421373363801477026083786683";
            String exponent = "65537";



            RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(exponent));
            RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(new BigInteger(modulus), new BigInteger(privateExponent));
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return new KeyPair(factory.generatePublic(publicSpec), factory.generatePrivate(privateSpec));

        } catch ( Exception e ) {

            throw new IllegalArgumentException(e);
        }
        *//*

    }*/
}

/**
 * Legacy Authorization Server does not support a custom name for the user parameter, so we'll need
 * to extend the default. By default, it uses the attribute {@code user_name}, though it would be
 * better to adhere to the {@code sub} property defined in the
 * <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JWT Specification</a>.
 */
class SubjectAttributeUserTokenConverter extends DefaultUserAuthenticationConverter {
    @Override
    public Map<String, ?> convertUserAuthentication(Authentication authentication) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sub", authentication.getName());
        if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
            response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
        }
        return response;
    }
}


