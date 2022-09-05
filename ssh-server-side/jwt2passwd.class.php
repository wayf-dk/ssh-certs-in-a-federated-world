<?php
class jwt2passwd {
    static function updateUserAndGroup($cert) {
        [$jwt,,] = sshCert::unpackString($cert['extensions']['groups@wayf.dk'], 0);
        $attrs = json_decode($jwt, 1);
        if ($attrs === false) {
            error_log(json_last_error_msg());
            print json_last_error_msg();
            exit;
        }
        error_log(print_r($attrs, 1));

        $username = $cert['valid principals'][0]; // for now - Key ID in the future
        $attrs['isMemberOf'][] = $username;

        // try to add user - will fail if already registered - we just ignore that
        $res = `/usr/sbin/adduser $username`;
        error_log("/usr/sbin/adduser $username ; '$res'");

        // we only add new groups never delete

        $attrs['isMemberOf'] = array_map(fn($member) => preg_replace("/\s/", "_", $member), $attrs['isMemberOf']);
        $groupList = join(' ', $attrs['isMemberOf']);
        error_log("groups $groupList");
        exec("/usr/bin/getent group $groupList | cut -d: -f1", $existingGroups, $result_code);
        error_log("existing groups '$result_code' ".print_r($existingGroups, 1));
        $newGroups = array_diff($attrs['isMemberOf'], $existingGroups, );
        error_log("add groups ".print_r($newGroups, 1));
        foreach($newGroups as $newGroup) {
            $res = system("/usr/sbin/addgroup --force-badname $newGroup");
            error_log("/usr/sbin/addgroup $newGroup ; $res");
        }

        $groups = join(",", $attrs['isMemberOf']);
        error_log("/usr/sbin/usermod -G $groups $username");
        exec("/usr/sbin/usermod -G $groups $username", $output, $result_code);
        error_log("moduser '$result_code ".print_r($output, 1));
        return $username;
    }
}
