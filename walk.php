<?php
 
$soft = array();
$result = snmpwalk('127.0.0.1', 'public', '.1.3.6.1.2.1.25.6.3.1', 1000000, 3);
$soft = array_chunk($result, count($result) / 5);
if ($soft != FALSE) {
    if (count($soft) > 0) {
        $data_fetched = 'yes';
 
        $installed_type = array();
        $installed_name = array();
        $installed_date = array();
        for ($i = 0; $i < count($soft[2]); $i++) {
            $installed_type[$i] = str_replace('INTEGER: ', '', $soft[2][$i]);
        }
 
        for ($i = 0; $i < count($soft[1]); $i++) {
            $split = explode(':', $soft[1][$i], 2);
            if (strcmp($split[0], 'Hex-STRING') == 0) {
                //		if ($hex) {
                $hex = str_replace(' ', '', $split[1]);
                //$snmp = str_replace(' ', '', $snmp);
                $hex = preg_replace('/[^a-zA-Z0-9]+/', '', $hex);
                $hex = hex2bin($hex);
                //}
                //$snmp = trim($snmp);
                //$output .= hexStr2Ascii($split[1]);
                //$hex = str_replace(' ', '', $split[1]);
                //$hex = str_replace('\r', '', $hex);
                //$hex = str_replace('\n', '', $hex);                            
                //$hexStrArr = explode(' ',$hexStr);
                //$hex='B0D9B6C8CDF8C5CC';
                //$string='';
                //for ($i=0; $i < strlen($hex)-1; $i+=2){
                //    $string .= mb_chr(hexdec($hex[$i].$hex[$i+1]));
                //}
                //$utf = "";
                //foreach($hexStrArr as $octet){
                //$codes = hexdec($octet);
                //if ($char > 0 ) { $asciiOut .= chr($char); }
                //if (is_scalar($codes)) $codes= func_get_args();
                //$str= '';
                // foreach ($codes as $code) $str.= html_entity_decode('&#'.$code.';',ENT_NOQUOTES,'UTF-8');
                //$utf=$utf.$str;
                //}
                //$string='';
                //for ($j=0; $j < strlen($hex)-1; $j+=2){
                //    $string .= mb_chr(hexdec($hex[$j].$hex[$j+1]));
                //}
                //mb_convert_encoding($hex, 'utf-8', 'gbk');
                $installed_name[$i] = $hex;
                //$str = mb_convert_encoding($str, "UTF-7", "EUC-JP");
            } else {
                $data = str_replace('STRING: ', '', $soft[1][$i]);
                $data = str_replace('"', '', $data);
                $installed_name[$i] = $data;
            }
        }
        for ($i = 0; $i < count($soft[3]); $i++) {
            $data = str_replace('STRING: ', '', $soft[3][$i]);
            $installed_date[$i] = $data;
        }
        print_r( $installed_type);
        print_r( $installed_name);
        print_r( $installed_date);
    } else {
        $data_fetched = 'no';
    }
} else {
    
}
