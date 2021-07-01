<?php

require 'vendor/autoload.php';

function hex2date($hexstring) {
    $date = "";

    $p = unpack("H*", substr($hexstring, 0, 2));  // year (2 byte)
    $date .= hexdec($p[1]) . "-";

    $p = unpack("H*", substr($hexstring, 2, 1));  // month (1 byte)
    $date .= sprintf("%02s", hexdec($p[1])) . "-";

    $p = unpack("H*", substr($hexstring, 3, 1));   // day (1 byte)
    $date .= sprintf("%02s", hexdec($p[1])) . " ";

    $p = unpack("H*", substr($hexstring, 4, 1));  // hour (1 byte)
    $date .= sprintf("%02s", hexdec($p[1])) . ":";

    $p = unpack("H*", substr($hexstring, 5, 1));  // minute (1 byte)
    $date .= sprintf("%02s", hexdec($p[1])) . ":";
    $p = unpack("H*", substr($hexstring, 6, 1));  // second (1 byte)
    $date .= sprintf("%02s", hexdec($p[1]));

    return ($date);
}

$snmp = new FreeDSx\Snmp\SnmpClient([
    'host' => '127.0.0.1',
    'version' => 2,
    'community' => 'public',
        ]);

# Get a specific OID value as a string...
echo $snmp->getValue('1.3.6.1.2.1.25.6.3.1.2.1') . PHP_EOL;

# Get a specific OID as an object...
$oid = $snmp->getOid('1.3.6.1.2.1.25.6.3.1.2.1');
var_dump($oid);

echo sprintf("%s == %s", $oid->getOid(), (string) $oid->getValue()) . PHP_EOL;

# Get multiple OIDs and iterate through them as needed...
$oids = $snmp->get('1.3.6.1.2.1.25.6.3.1.2.1', '1.3.6.1.2.1.25.6.3.1.2.2', '1.3.6.1.2.1.25.6.3.1.2.3');

foreach ($oids as $oid) {
    echo sprintf("%s == %s", $oid->getOid(), (string) $oid->getValue()) . PHP_EOL;
}

# Using the SnmpClient, get the helper class for an SNMP walk...
$walk = $snmp->walk('1.3.6.1.2.1.25.6.3.1');

# Keep the walk going until there are no more OIDs left
while ($walk->hasOids()) {
    try {
        # Get the next OID in the walk
        $oid = $walk->next();
        if (strpos($oid->getOid(), '1.3.6.1.2.1.25.6.3.1.2') !== false) {
            echo sprintf("%s = %s", $oid->getOid(), mb_convert_encoding($oid->getValue(), "utf8", "gbk")) . PHP_EOL;
        }
        if (strpos($oid->getOid(), '1.3.6.1.2.1.25.6.3.1.5') !== false) {
            echo sprintf("%s = %s", $oid->getOid(), hex2date($oid->getValue())) . PHP_EOL;
        }
    } catch (\Exception $e) {
        # If we had an issue, display it here (network timeout, etc)
        echo "Unable to retrieve OID. " . $e->getMessage() . PHP_EOL;
    }
}

echo sprintf("Walked a total of %s OIDs.", $walk->count()) . PHP_EOL;
