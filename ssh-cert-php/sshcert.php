<?php
set_include_path(__DIR__."/templates");
$path = array_values(array_filter(preg_split("/[\/?]/", $_SERVER['REQUEST_URI'] ?? ''), function ($e) { return $e; })); // get rid of falsy elements
//var_dump('<pre>', $_SERVER, $path); exit;
[$do, $scope] = $path + [null, null];
switch ($do) {
    case "getc":
        $token = $scope;
        session_id($token); // which is now token
        session_start(['cookie_samesite' => 'None', 'cookie_secure' => true]);
        if ($_SESSION['principals'] ?? false) {
            print genCert($_POST['pub']);
            break;
        }
        http_response_code(204);
        break;
    default:
        session_start(['cookie_samesite' => 'None', 'cookie_secure' => true]);
        $loggedIn = $_SESSION['principals'] ?? false;
        if (!$loggedIn || $do == "login") {
            $_SESSION = [];
            session_regenerate_id();
            //$attrs = saml2jwt::jwtauth([$scope]);
            $attrs = [
                'eduPersonPrincipalName' => ['user2@sshca.lan'],
                'memberOf' => ['group1', 'group-x'],
            ];

            preg_match('/^.+@([^@]+)/', $attrs['eduPersonPrincipalName'][0], $d);
            [$eppn, $scope] = $d;
            $_SESSION['principals'] = [preg_replace("/[^-a-z0-9]/", "_", $eppn)];
            $_SESSION['attrs'] = $attrs;
            header("Location: https://sshca.lan/show/$scope");
            exit;
        }
        $sessionId = session_id();
        print templates::render('body', compact('sessionId'));
        break;
}

function genCert($pubKey) {
    $attrs = [
        'eduPersonPrincipalName' => ['user2@sshca.lan'],
        'memberOf' => ['group1', 'group-y'],
    ];

    preg_match('/^.+@([^@]+)/', $attrs['eduPersonPrincipalName'][0], $d);
    [$eppn, $scope] = $d;
    $_SESSION['principals'] = [preg_replace("/[^-a-z0-9]/", "_", $eppn)];
    $_SESSION['attrs'] = $attrs;

    $principals = join(",", $_SESSION['principals']);
    $keyID = $_SESSION['principals'][0];
    $privatekey = __DIR__."/ssh-ca-key";
    $pubfile = tempnam("/tmp", "pub-");
    file_put_contents($pubfile, $pubKey);
    $certfile = "$pubfile-cert.pub";
    $attrs = $_SESSION['attrs'];
    $jsonattrs = json_encode($attrs);
    // -O 'critical:force-command=/usr/bin/echo hi'
    $out = `ssh-keygen -q -O 'extension:groups@wayf.dk=$jsonattrs' -s '$privatekey' -n '$principals' -I '$eppn' -V -1d:+1d $pubfile 2>&1`;
    print $out;
    $cert = file_get_contents($certfile);
    unlink($certfile);
    unlink($pubfile);
    return $cert;
}

class saml2jwt {
    static $cert = 'MIIC7TCCAdWgAwIBAgIBBzANBgkqhkiG9w0BAQsFADAwMQswCQYDVQQGEwJESzENMAsGA1UEChMEV0FZRjESMBAGA1UEAxMJd2F5Zi4yMDE2MB4XDTE1MDEwMTAwMDAwMFoXDTI1MTIzMTAwMDAwMFowMDELMAkGA1UEBhMCREsxDTALBgNVBAoTBFdBWUYxEjAQBgNVBAMTCXdheWYuMjAxNjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOeCt61E+O909jreVUV1tFHQe9m3h612W38OauWftVVrwH0CJpYCFGAMUBcDFkPgocA+XpB2qadF+/dnErIDbTVgxqyewB0TOWmMoqMknrkmS0x0AiRHIBtkzIWFam+EwGtFGA5Hw3sjGPoDXg4cGT731uoCktsH5ELt+eFDXSBOUgxyKzZf8NTXRbLksIdPxNgZ04e5JawFo1cnYbTVYQcleMqOYY3rIDXxA8BTm4ZYCNkxLO0v7YK7+mfF5T1Q5C7FXivoQI+A2mi/qGlwLt+oD81jdYki/v7ApXZi0sdcRovA9H4yFCv4tT5f/Plu8YJ8aXSGpJ8gATPtkY9ul9cCAwEAAaMSMBAwDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4IBAQCaDrkKvC9mc8cOmjFhPd/4UgZxol7K0U7GwBY92MXzdE/o4Dd+u3Dw0+O3UsK2kxExFlT3qXuG9XF987xUoGBy+Ip6A14nmKfW9a1hLS7zZoTVpxHebmms8n5voKLPBWowiMwb8jLdVaPzAx7bMnOfXrV3g0L8inPsqgYOgqku9//8I7YnV/r8z0V0uLgi2n9eYDyqvktsL37tIw6RTX/l9J8KQlHy0eWMs9CXDaK1gYdif1EsaHW4xLpjZsohIoovXMtQNTN+jIybXdEDScdLzwT9j9+BU9uHJRx3f3bfwX9QINsDkafDOtBNAnW762LHylOBiXgV2s954JAVY3O+';
    static $saml2jwt = 'https://wayf.wayf.dk/saml2jwt';
    static $issuer = 'http://ssh-ca.deic.dk';
    static $idplist = [];
    static $acs = 'https://ssh-cert.dgw.deic.dk/acs';
    static $ssl = ['verify_peer' => true, 'verify_peer_name' => true];
    static function jwtauth($idplist) {
        $query = ['acs' =>  self::$acs, 'issuer' =>  self::$issuer];
        if (empty($_POST['SAMLResponse'])) {
            $query['idplist'] = join(',', $idplist ?? self::$idplist);
            $opts = ['http'=> ['follow_location' => 0], 'ssl' => self::$ssl];
            file_get_contents(self::$saml2jwt . '?' . http_build_query($query), false, stream_context_create($opts));
            //var_dump($http_response_header); exit;
            array_walk($http_response_header, function($header) { if (preg_match('/^Set-Cookie: /i', $header)) { return; } header($header, false); });
            exit;
        } else {
            unset($_POST['RelayState']);
            $opts = ['http'=> ['method'  => 'POST',
                               'content' => http_build_query(array_merge($query, $_POST)),
                               'header'  => "Content-Type: application/x-www-form-urlencoded", ], '
                                ssl' => self::$ssl];
            $jwt = file_get_contents(self::$saml2jwt, false, stream_context_create($opts));
            list($header, $body, $signature) = explode(".", $jwt);
            $cert = "-----BEGIN CERTIFICATE-----\n" . wordwrap(self::$cert, 64, "\n", true) . "\n-----END CERTIFICATE-----\n";
            $pubkey = openssl_pkey_get_public($cert);

            $ok = openssl_verify("$header.$body", self::base64url_decode($signature), $pubkey, 'SHA256');
            return  $ok === 1 ? json_decode(self::base64url_decode($body), true) : [];
        }
    }
    static function base64url_decode($b64url) { return base64_decode(strtr($b64url, '-_', '+/')); }
}

class templates {
    static function render($template, $content, $super = array('main'))
    {
        if (is_array($content)) {
            extract($content);
        } // Extract the vars to local namespace
        if (!isset($debug)) {
            $debug = '';
        }
        ob_start(); // Start output buffering
        include($template . '.tmpl'); // Include the file
        $content = ob_get_contents(); // Get the content of the buffer
        ob_end_clean(); // End buffering and discard
        if ($super) {
            return self::render(array_shift($super), compact('content', 'debug'), $super); # array_shift shifts one element from super ...
        }
        return $content; // Return the content
    }
}
