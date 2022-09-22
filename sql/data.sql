INSERT INTO oauth2_registered_client 
    (id, client_id, client_secret, client_name, client_authentication_methods,
     authorization_grant_types, redirect_uris, scopes, client_settings, token_settings)
VALUES
    (
        '2537297a-a653-4c1a-90e9-3da90a753e44',
        'expense-client',
        '{bcrypt}$2a$10$dAD6vI2RBE9WcFG3ROw4HePMBABC6UQAk45lF06NfDyvN42kLi0KW',
        'expense-client',
        'client_secret_basic',
        'refresh_token,authorization_code',
        'http://127.0.0.1:8080/login/oauth2/code/expense-client-authorization-code',
        'openid,expense.all,category.read,importance.read',
        '{"@class":"java.util.Collections$UnmodifiableMap",
        "settings.client.require-proof-key":false,
        "settings.client.require-authorization-consent":false}',
        '{"@class":"java.util.Collections$UnmodifiableMap",
        "settings.token.reuse-refresh-tokens":true,
        "settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],
        "settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],
        "settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.core.OAuth2TokenFormat","value":"self-contained"},
        "settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000]}'
    );

INSERT INTO users (username, password, enabled) VALUES ('admin','{noop}password','1');

INSERT INTO authorities (username, authority) VALUES ('admin','USER');
