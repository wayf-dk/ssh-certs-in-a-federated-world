<?php
spl_autoload_extensions('.class.php');
spl_autoload_register();
set_include_path(__DIR__."/templates:".dirname(__DIR__)."/ssh-server-side");
$path = array_values(array_filter(preg_split("/[\/?]/", $_SERVER['REQUEST_URI'] ?? ''), function ($e) { return $e; })); // get rid of falsy elements
//var_dump('<pre>', $_SERVER, $path); exit;

/*
    hengill
    hromundartindur
    blafjoll
    krisuvik
    reykjanes
    svartsengi
    eldey
*/

class demo {
    static $attrs = [
        'eduPersonPrincipalName' => ['eldey@sshca.lan'],
        'isMemberOf' => ['group-1', 'group-2', 'group-3', 'group-44'],
    ];
}

[$do, $scope] = $path + [null, null];

switch ($do) {
    case "favicon.ico":
        exit;
    default:
        $attrs = demo::$attrs;
        //$attrs = saml2jwt::jwtauth([$scope]);
        $fn = tempnam("/var/run/sshca", "");
        file_put_contents($fn, json_encode($attrs));
        chmod($fn, 0666);
        $token = array_reverse(explode("/", $fn))[0];
        $principal = preg_replace("/[^-a-z0-9]/", "_", $attrs['eduPersonPrincipalName'][0]);
        print templates::render('body', compact('token', 'principal'));
        exit;
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

class saml2jwt {
    static $cert = 'MIIC7TCCAdWgAwIBAgIBBzANBgkqhkiG9w0BAQsFADAwMQswCQYDVQQGEwJESzENMAsGA1UEChMEV0FZRjESMBAGA1UEAxMJd2F5Zi4yMDE2MB4XDTE1MDEwMTAwMDAwMFoXDTI1MTIzMTAwMDAwMFowMDELMAkGA1UEBhMCREsxDTALBgNVBAoTBFdBWUYxEjAQBgNVBAMTCXdheWYuMjAxNjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOeCt61E+O909jreVUV1tFHQe9m3h612W38OauWftVVrwH0CJpYCFGAMUBcDFkPgocA+XpB2qadF+/dnErIDbTVgxqyewB0TOWmMoqMknrkmS0x0AiRHIBtkzIWFam+EwGtFGA5Hw3sjGPoDXg4cGT731uoCktsH5ELt+eFDXSBOUgxyKzZf8NTXRbLksIdPxNgZ04e5JawFo1cnYbTVYQcleMqOYY3rIDXxA8BTm4ZYCNkxLO0v7YK7+mfF5T1Q5C7FXivoQI+A2mi/qGlwLt+oD81jdYki/v7ApXZi0sdcRovA9H4yFCv4tT5f/Plu8YJ8aXSGpJ8gATPtkY9ul9cCAwEAAaMSMBAwDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4IBAQCaDrkKvC9mc8cOmjFhPd/4UgZxol7K0U7GwBY92MXzdE/o4Dd+u3Dw0+O3UsK2kxExFlT3qXuG9XF987xUoGBy+Ip6A14nmKfW9a1hLS7zZoTVpxHebmms8n5voKLPBWowiMwb8jLdVaPzAx7bMnOfXrV3g0L8inPsqgYOgqku9//8I7YnV/r8z0V0uLgi2n9eYDyqvktsL37tIw6RTX/l9J8KQlHy0eWMs9CXDaK1gYdif1EsaHW4xLpjZsohIoovXMtQNTN+jIybXdEDScdLzwT9j9+BU9uHJRx3f3bfwX9QINsDkafDOtBNAnW762LHylOBiXgV2s954JAVY3O+';
    static $saml2jwt = 'https://wayf.wayf.dk/saml2jwt';
    static $issuer = 'http://ssh-ca.deic.dk';
    static $idplist = [];
    static $acs = 'https://sshca.lan';
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

