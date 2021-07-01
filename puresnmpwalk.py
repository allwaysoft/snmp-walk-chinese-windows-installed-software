from puresnmp import walk
import struct, pytz, datetime


def decode_snmp_date(octetstr: bytes) -> datetime.datetime:
    size = len(octetstr)
    if size == 8:
        (year, month, day, hour, minutes,
         seconds, deci_seconds,
         ) = struct.unpack('>HBBBBBB', octetstr)
        return datetime.datetime(
            year, month, day, hour, minutes, seconds,
            deci_seconds * 100_000, tzinfo=pytz.utc)
    elif size == 11:
        (year, month, day, hour, minutes,
         seconds, deci_seconds, direction,
         hours_from_utc, minutes_from_utc,
         ) = struct.unpack('>HBBBBBBcBB', octetstr)
        offset = datetime.timedelta(
            hours=hours_from_utc, minutes=minutes_from_utc)
        if direction == b'-':
            offset = -offset
        return datetime.datetime(
            year, month, day, hour, minutes, seconds,
            deci_seconds * 100_000, tzinfo=pytz.utc) + offset
    raise ValueError("The provided OCTETSTR is not a valid SNMP date")


IP = "127.0.0.1"
COMMUNITY = 'public'
OID = '1.3.6.1.2.1.25.6.3.1'

for row in walk(IP, COMMUNITY, OID):

    if (str(row.oid)).__contains__("1.3.6.1.2.1.25.6.3.1.2"):
        print(row.oid, ' = ', row.value.decode('GBK', 'strict'))
    elif (str(row.oid)).__contains__("1.3.6.1.2.1.25.6.3.1.5"):
        print(row.oid, ' = ', decode_snmp_date(row.value))
    else:
        print(row.oid, ' = ', row.value)
