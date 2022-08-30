<?php

class sshCert {
    static $fields = [
        'common' => [
            "serial"           => '8',
            "type"             => '4',
            "key id"           => 's',
            "valid principals" => 'S',
            "valid after"      => '8',
            "valid before"     => '8',
            "critical options" => 'X',
            "extensions"       => 'X',
            "reserved"         => 's',
            "signature key"    => 's',
            "signature"        => 's',
        ],

        "ssh-rsa-cert-v01@openssh.com" => [
            "nonce" => 's',
            "e"     => 'm',
            "n"     => 'm',
        ],

        "ssh-dss-cert-v01@openssh.com" => [
            "nonce" => 's',
            "p"     => 'm',
            "q"     => 'm',
            "g"     => 'm',
            "y"     => 'm',
        ],

        "ecdsa-sha2-nistp256-cert-v01@openssh.com" => [
            "nonce"      => 's',
            "curve"      => 's',
            "public_key" => 's',
        ],

	    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" => [
	         "nonce"       => 's',
	         "curve name"  => 's',
	         "Q"           => 's',
	         "application" => 's'
        ],

        "ssh-ed25519-cert-v01@openssh.com" => [
            'nonce' => 's',
            'pk'    => 's',
        ],
    ];

    static function decodeCert($cert) {
        self::$fields["ecdsa-sha2-nistp384-cert-v01@openssh.com"] = self::$fields["ecdsa-sha2-nistp256-cert-v01@openssh.com"];
        self::$fields["ecdsa-sha2-nistp521-cert-v01@openssh.com"] = self::$fields["ecdsa-sha2-nistp256-cert-v01@openssh.com"];

        $cert = base64_decode($cert);
        [$keyType,, $offset] = self::unpackString($cert, 0);
        $format = self::$fields[$keyType]+self::$fields['common'];
        $res = [];
        foreach($format as $n => $f) {
            switch ($f) {
                case "s":
                case "m":
                    [$res[$n],, $offset] = self::unpackString($cert, $offset);
                break;
                case "S": // list of strings
                    [$txt, $l, $offset] = self::unpackString($cert, $offset);
                    $res[$n] = [];
                    $offset2 = 0;
                    while ($offset2 < $l) {
                        [$res[$n][],, $offset2] = self::unpackString($txt, $offset2); // key
                    };
                break;
                case "X": // key value pairs
                    [$txt, $l, $offset] = self::unpackString($cert, $offset);
                    $offset2 = 0;
                    while ($offset2 < $l) {
                        [$k,, $offset2] = self::unpackString($txt, $offset2); // key
                        [$v, $ll, $offset2] = self::unpackString($txt, $offset2); // data
                        // $v is just a blob, if it is a string it still has a 4 byte length prefix
                        $res[$n][$k] = $v;
                    };
                break;
                case "4":
                    $res[$n] = unpack("N", $cert, $offset)[1];
                    $offset += 4;
                break;
                case "8":
                    $res[$n] = unpack("J", $cert, $offset)[1];
                    $offset += 8;
                break;
            }
        }
        return $res;
    }

    static function unpackString($buf, $offset) {
        $l = unpack("N", $buf, $offset)[1];
        $res = unpack("a$l", $buf, $offset + 4)[1];
        return [$res, $l, $offset + $l + 4];
    }
}